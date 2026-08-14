import json
import socket
import threading
import time


class LocalBridge:
    def __init__(
        self,
        app_name,
        host="127.0.0.1",
        port=50555,
        on_message=None,
        on_status=None,
        auth_token=None,
        autostart_server=True,
    ):
        self.app_name = app_name
        self.host = host
        self.port = port
        self.on_message = on_message
        self.on_status = on_status
        self.auth_token = auth_token
        self.autostart_server = autostart_server

        self._running = False
        self._server_socket = None
        self._client_socket = None
        self._clients = []
        self._lock = threading.Lock()
        self._connected = False
        self._status = "offline"

    @property
    def connected(self):
        return self._connected

    def _set_status(self, status):
        if status == self._status:
            return
        self._status = status
        if callable(self.on_status):
            self.on_status(status)

    def start(self):
        if self._running:
            return self.connected

        self._running = True
        self._set_status("connecting")
        if not self._connect_client() and self.autostart_server:
            self._start_server()
            time.sleep(0.15)
            self._connect_client()

        if not self.connected:
            self._set_status("disconnected")

        return self.connected

    def reconnect(self):
        if not self._running:
            self._running = True

        self._set_status("connecting")
        if self._client_socket is not None:
            try:
                self._client_socket.close()
            except OSError:
                pass
            self._client_socket = None
            self._connected = False

        if self._connect_client():
            return True

        if self.autostart_server and self._server_socket is None:
            self._start_server()
            time.sleep(0.15)
            if self._connect_client():
                return True

        self._set_status("disconnected")
        return False

    def stop(self):
        self._running = False

        with self._lock:
            clients = list(self._clients)
            self._clients.clear()

        for client in clients:
            try:
                client.close()
            except OSError:
                pass

        if self._client_socket is not None:
            try:
                self._client_socket.close()
            except OSError:
                pass
            self._client_socket = None
            self._connected = False

        if self._server_socket is not None:
            try:
                self._server_socket.close()
            except OSError:
                pass
            self._server_socket = None

        self._set_status("offline")

    def send(self, event_type, payload=None):
        if not self._running:
            return False

        if self._client_socket is None:
            if not self._connect_client():
                self._set_status("disconnected")
                return False

        message = {
            "source": self.app_name,
            "type": event_type,
            "payload": payload or {},
            "ts": time.time(),
        }
        if self.auth_token:
            message["token"] = self.auth_token
        data = (json.dumps(message) + "\n").encode("utf-8")

        try:
            self._client_socket.sendall(data)
            return True
        except OSError:
            self._client_socket = None
            self._connected = False
            self._set_status("disconnected")
            return False

    def _start_server(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        try:
            server.bind((self.host, self.port))
            server.listen(5)
        except OSError:
            server.close()
            return

        self._server_socket = server
        self._set_status("listening")

        accept_thread = threading.Thread(target=self._accept_loop, daemon=True)
        accept_thread.start()

    def _accept_loop(self):
        while self._running and self._server_socket is not None:
            try:
                conn, _ = self._server_socket.accept()
                conn.settimeout(1.0)
            except OSError:
                break

            with self._lock:
                self._clients.append(conn)

            thread = threading.Thread(
                target=self._server_client_loop,
                args=(conn,),
                daemon=True,
            )
            thread.start()

    def _server_client_loop(self, conn):
        buffer = ""
        try:
            while self._running:
                try:
                    chunk = conn.recv(4096)
                except socket.timeout:
                    continue

                if not chunk:
                    break

                buffer += chunk.decode("utf-8", errors="ignore")
                while "\n" in buffer:
                    line, buffer = buffer.split("\n", 1)
                    line = line.strip()
                    if not line:
                        continue
                    self._broadcast(line + "\n", exclude=conn)
        except OSError:
            pass
        finally:
            with self._lock:
                if conn in self._clients:
                    self._clients.remove(conn)
            try:
                conn.close()
            except OSError:
                pass

    def _broadcast(self, raw_line, exclude=None):
        dead = []
        with self._lock:
            targets = list(self._clients)

        encoded = raw_line.encode("utf-8")
        for client in targets:
            if client is exclude:
                continue
            try:
                client.sendall(encoded)
            except OSError:
                dead.append(client)

        if dead:
            with self._lock:
                for dead_client in dead:
                    if dead_client in self._clients:
                        self._clients.remove(dead_client)

    def _connect_client(self):
        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.settimeout(1.5)

        try:
            client.connect((self.host, self.port))
            client.settimeout(1.0)
        except OSError:
            client.close()
            return False

        self._client_socket = client
        self._connected = True
        self._set_status("connected")
        listen_thread = threading.Thread(target=self._client_loop, daemon=True)
        listen_thread.start()
        self.send("bridge.hello", {"app": self.app_name})
        return True

    def _client_loop(self):
        buffer = ""
        while self._running and self._client_socket is not None:
            try:
                chunk = self._client_socket.recv(4096)
            except socket.timeout:
                continue
            except OSError:
                break

            if not chunk:
                break

            buffer += chunk.decode("utf-8", errors="ignore")
            while "\n" in buffer:
                line, buffer = buffer.split("\n", 1)
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if self.auth_token and message.get("token") != self.auth_token:
                    continue
                if callable(self.on_message):
                    self.on_message(message)

        self._client_socket = None
        self._connected = False
        if self._running:
            self._set_status("disconnected")

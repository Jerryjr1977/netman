#websocket_utils
import asyncio
import websockets
import json
import logging
import threading
import queue
from typing import Dict, List, Optional, Callable, Any
import ssl
import re

logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
logger = logging.getLogger(__name__)

class WebSocketInterceptor:
    """WebSocket connection interceptor for MITM proxy."""

    def __init__(self):
        self.connections = {}  # client_id -> connection info
        self.message_queue = queue.Queue()
        self.intercept_enabled = True
        self.modification_rules = []

    def add_modification_rule(self, rule_func: Callable[[str, bool], str]) -> None:
        """Add a message modification rule.

        Args:
            rule_func: Function that takes (message, is_outgoing) and returns modified message
        """
        self.modification_rules.append(rule_func)
        logger.info(f"Added WebSocket modification rule (total: {len(self.modification_rules)})")

    def intercept_websocket_upgrade(self, request_data: bytes) -> Optional[Dict[str, Any]]:
        """Check if request is WebSocket upgrade and extract connection info.

        Args:
            request_data: Raw HTTP request bytes

        Returns:
            Connection info dict or None if not WebSocket
        """
        try:
            request_str = request_data.decode('utf-8', errors='ignore')
            headers = {}

            # Parse headers
            lines = request_str.split('\r\n')
            if not lines:
                return None

            # Check for WebSocket upgrade
            for line in lines[1:]:
                if ': ' in line:
                    key, value = line.split(': ', 1)
                    headers[key.lower()] = value

            if (headers.get('upgrade', '').lower() == 'websocket' and
                headers.get('connection', '').lower() == 'upgrade' and
                'sec-websocket-key' in headers):

                return {
                    'host': headers.get('host', ''),
                    'path': lines[0].split()[1] if len(lines[0].split()) > 1 else '/',
                    'sec_websocket_key': headers.get('sec-websocket-key'),
                    'sec_websocket_version': headers.get('sec-websocket-version', '13'),
                    'origin': headers.get('origin', ''),
                    'subprotocols': headers.get('sec-websocket-protocol', '').split(', ')
                }

        except Exception as e:
            logger.debug(f"WebSocket upgrade parsing failed: {e}")

        return None

    def generate_websocket_accept(self, key: str) -> str:
        """Generate Sec-WebSocket-Accept header value.

        Args:
            key: Sec-WebSocket-Key header value

        Returns:
            Accept header value
        """
        import hashlib
        import base64

        magic_string = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        combined = key + magic_string
        hashed = hashlib.sha1(combined.encode()).digest()
        return base64.b64encode(hashed).decode()

    def modify_message(self, message: str, is_outgoing: bool) -> str:
        """Apply modification rules to WebSocket message.

        Args:
            message: Original message
            is_outgoing: True if message is from client to server

        Returns:
            Modified message
        """
        if not self.intercept_enabled:
            return message

        modified = message
        for rule in self.modification_rules:
            try:
                modified = rule(modified, is_outgoing)
            except Exception as e:
                logger.warning(f"WebSocket modification rule failed: {e}")

        if modified != message:
            logger.info(f"WebSocket message modified: {len(message)} -> {len(modified)} chars")

        return modified

    def log_message(self, client_id: str, message: str, is_outgoing: bool) -> None:
        """Log WebSocket message to queue for GUI display.

        Args:
            client_id: Unique client identifier
            message: Message content
            is_outgoing: True if from client to server
        """
        direction = "CLIENT -> SERVER" if is_outgoing else "SERVER -> CLIENT"
        log_entry = {
            'type': 'websocket',
            'client_id': client_id,
            'direction': direction,
            'message': message,
            'timestamp': asyncio.get_event_loop().time() if asyncio.get_event_loop() else 0
        }

        self.message_queue.put(("WEBSOCKET", f"[{client_id}] {direction}: {message[:200]}{'...' if len(message) > 200 else ''}"))

    async def handle_websocket_connection(self, client_ws, server_ws, client_id: str) -> None:
        """Handle bidirectional WebSocket message proxying.

        Args:
            client_ws: Client WebSocket connection
            server_ws: Server WebSocket connection
            client_id: Unique client identifier
        """
        try:
            # Create tasks for both directions
            client_to_server = asyncio.create_task(
                self._proxy_messages(client_ws, server_ws, client_id, True)
            )
            server_to_client = asyncio.create_task(
                self._proxy_messages(server_ws, client_ws, client_id, False)
            )

            # Wait for either direction to close
            await asyncio.gather(client_to_server, server_to_client, return_exceptions=True)

        except Exception as e:
            logger.error(f"WebSocket connection error for {client_id}: {e}")
        finally:
            # Clean up connections
            try:
                await client_ws.close()
                await server_ws.close()
            except:
                pass

    async def _proxy_messages(self, source_ws, dest_ws, client_id: str, is_outgoing: bool) -> None:
        """Proxy messages from source to destination WebSocket.

        Args:
            source_ws: Source WebSocket
            dest_ws: Destination WebSocket
            client_id: Client identifier
            is_outgoing: True if client -> server
        """
        try:
            async for message in source_ws:
                # Log original message
                self.log_message(client_id, message, is_outgoing)

                # Apply modifications
                modified_message = self.modify_message(message, is_outgoing)

                # Send modified message
                await dest_ws.send(modified_message)

        except websockets.exceptions.ConnectionClosed:
            logger.debug(f"WebSocket connection closed for {client_id}")
        except Exception as e:
            logger.error(f"WebSocket message proxy error for {client_id}: {e}")

# Global interceptor instance
websocket_interceptor = WebSocketInterceptor()

def get_websocket_interceptor() -> WebSocketInterceptor:
    """Get the global WebSocket interceptor instance."""
    return websocket_interceptor
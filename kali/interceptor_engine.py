#interceptor_engine
import threading

is_enabled = False
intercept_event = threading.Event()
drop_flag = False
modified_data = ""
target_methods = {"GET" : False,
                  "POST" : False,
                  "PUT" : False,
                  "PATCH" : False,
                  "DELETE" : False,
                  "OPTIONS" : False}
target_path = "" 

def toggle():
    global is_enabled
    is_enabled = not is_enabled
    if not is_enabled:
        intercept_event.set()
    return is_enabled

def forward_request(data):
    global modified_data, drop_flag
    modified_data = data
    drop_flag = False
    intercept_event.set()

def drop_request():
    global drop_flag
    drop_flag = True
    intercept_event.set()

def wait_for_user():
    intercept_event.wait()
    intercept_event.clear()
    return drop_flag, modified_data
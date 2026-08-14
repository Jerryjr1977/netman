#logger_engine
import os

def read_log(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r') as f:
            log_data = f.read()
            if log_data:
                return log_data
            else:
                return ""
            
def clear_log(file_path):
    if os.path.exists(file_path):
        with open(file_path, "w", encoding="utf-8") as f:
            f.write("")

def append_log(file_path, data):
    with open(file_path, 'a') as f:
        f.write(data)
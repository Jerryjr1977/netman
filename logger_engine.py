#logger_engine
import os

def read_log(file_path):
    if os.path.exists(file_path):
        with open(file_path, 'r', encoding='utf-8', errors='replace') as f:
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
    with open(file_path, 'a', encoding='utf-8', errors='replace') as f:
        f.write(data)
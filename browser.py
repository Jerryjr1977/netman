#browser
import os
import shutil
import subprocess
import sys


def launch_firefox():
    # Keep Windows profile behavior, but support Linux/macOS gracefully.
    if sys.platform.startswith("win"):
        subprocess.Popen([r"C:\Program Files\Mozilla Firefox\firefox.exe", "-P", "NetMan"])
        return

    firefox_bin = shutil.which("firefox")
    if firefox_bin:
        subprocess.Popen([firefox_bin])
        return

    xdg_open = shutil.which("xdg-open")
    if xdg_open:
        subprocess.Popen([xdg_open, "http://127.0.0.1:8080"])
        return

    if sys.platform == "darwin":
        subprocess.Popen(["open", "http://127.0.0.1:8080"])
        return

    raise FileNotFoundError("No browser found (firefox/xdg-open/open)")

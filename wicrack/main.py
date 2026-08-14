import tkinter as tk
try:
    from .gui import WiCrackGUI
except ImportError:
    from gui import WiCrackGUI


def main():
    root = tk.Tk()
    app = WiCrackGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
# Local Environment (VM Copy)

This project is now running from the VM-local path:

- `/home/kali/netman_kali`

Use this virtual environment for this copy only:

## 1) Create the venv (if missing)

```bash
cd "/home/kali/netman_kali"
python3 -m venv .venv
```

## 2) Activate it

```bash
source "/home/kali/netman_kali/.venv/bin/activate"
```

## 3) Install dependencies

```bash
pip install -r "/home/kali/netman_kali/requirements.txt"
```

## 4) Run NetMan

```bash
python "/home/kali/netman_kali/gui_test.py"
```

## 5) Deactivate when done

```bash
deactivate
```

## Notes

- This folder is independent from the host shared folder.
- Changes here stay in the VM local filesystem.
- If imports fail after moving files, recreate the venv and reinstall from `requirements.txt`.

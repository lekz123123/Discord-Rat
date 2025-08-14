import os
import shutil
import sys

# --- Paths ---
# Source DLL (where you keep the downloaded libopus.dll)
SOURCE_DLL = os.path.abspath("libopus.dll")

# Python installation base path
PYTHON_BASE = sys.base_prefix  # handles venvs or system installs

# Destination DLL path
DLL_DEST = os.path.join(PYTHON_BASE, "DLLs", "libopus.dll")

# Path to opuslib/api/__init__.py
OPUSLIB_INIT = os.path.join(
    PYTHON_BASE, "Lib", "site-packages", "opuslib", "api", "__init__.py"
)

# --- 1. Copy DLL ---
if not os.path.exists(SOURCE_DLL):
    raise FileNotFoundError(f"Source DLL not found: {SOURCE_DLL}")

print(f"Copying {SOURCE_DLL} → {DLL_DEST}")
os.makedirs(os.path.dirname(DLL_DEST), exist_ok=True)
shutil.copy2(SOURCE_DLL, DLL_DEST)

# --- 2. Overwrite opuslib/api/__init__.py ---
dll_path_str = DLL_DEST.replace("\\", "\\\\")  # escape backslashes for Python string

INIT_CONTENT = f"""#!/usr/bin/env python
# -*- coding: utf-8 -*-
# pylint: disable=invalid-name

\"\"\"OpusLib Package.\"\"\"

import ctypes  # type: ignore

__author__ = 'Никита Кузнецов <self@svartalf.info>'
__copyright__ = 'Copyright (c) 2012, SvartalF'
__license__ = 'BSD 3-Clause License'

# Hardcoded DLL path
dll_path = r\"{dll_path_str}\"

try:
    libopus = ctypes.CDLL(dll_path)
except Exception as e:
    raise Exception(f"Could not load Opus DLL at {{dll_path}}: {{e}}")

c_int_pointer = ctypes.POINTER(ctypes.c_int)
c_int16_pointer = ctypes.POINTER(ctypes.c_int16)
c_float_pointer = ctypes.POINTER(ctypes.c_float)
"""

print(f"Overwriting {OPUSLIB_INIT}")
with open(OPUSLIB_INIT, "w", encoding="utf-8") as f:
    f.write(INIT_CONTENT)

print("✔ Opus setup complete.")

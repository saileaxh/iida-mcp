"""Auto-install iida-mcp-ioctl kernel driver via UAC elevation.
Looks for a signed iida-mcp-ioctl.sys near the plugin and installs+starts it
as a kernel service. After the first successful start, subsequent IDA sessions
detect the running driver and skip the UAC prompt."""
import os
import sys
import ctypes
from ctypes import wintypes

SERVICE_NAME = 'iida-mcp-ioctl'
DEVICE_PATH = r'\\.\iida-mcp-ioctl'

GENERIC_READ = 0x80000000
OPEN_EXISTING = 3
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value
SEE_MASK_NOCLOSEPROCESS = 0x40


def is_driver_running():
    """Try to open the driver device. True if the device is accessible."""
    try:
        kernel32 = ctypes.windll.kernel32
        CreateFileW = kernel32.CreateFileW
        CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
            ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        CreateFileW.restype = wintypes.HANDLE
        h = CreateFileW(DEVICE_PATH, GENERIC_READ, 0, None, OPEN_EXISTING, 0, None)
        if not h or h == INVALID_HANDLE_VALUE:
            return False
        kernel32.CloseHandle(h)
        return True
    except Exception:
        return False


def _plugin_dir():
    return os.path.dirname(os.path.abspath(__file__))


def _find_sys():
    """Look for iida-mcp-ioctl.sys near the plugin."""
    here = _plugin_dir()
    candidates = [
        os.path.join(here, '..', 'iida-mcp-ioctl.sys'),
        os.path.join(here, 'iida-mcp-ioctl.sys'),
        os.path.join(here, '..', 'driver', 'iida-mcp-ioctl.sys'),
    ]
    for p in candidates:
        full = os.path.abspath(p)
        if os.path.isfile(full):
            return full
    return None


class _SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [
        ('cbSize', wintypes.DWORD),
        ('fMask', wintypes.ULONG),
        ('hwnd', wintypes.HWND),
        ('lpVerb', wintypes.LPCWSTR),
        ('lpFile', wintypes.LPCWSTR),
        ('lpParameters', wintypes.LPCWSTR),
        ('lpDirectory', wintypes.LPCWSTR),
        ('nShow', ctypes.c_int),
        ('hInstApp', wintypes.HINSTANCE),
        ('lpIDList', ctypes.c_void_p),
        ('lpClass', wintypes.LPCWSTR),
        ('hkeyClass', wintypes.HKEY),
        ('dwHotKey', wintypes.DWORD),
        ('hIconOrMonitor', wintypes.HANDLE),
        ('hProcess', wintypes.HANDLE),
    ]


def _install_and_start(sys_path):
    """Spawn an elevated PowerShell that copies the .sys to System32\\drivers,
    registers it as a kernel service, and starts it. Blocks up to 30s."""
    system_root = os.environ.get('SystemRoot', r'C:\Windows')
    dst = os.path.join(system_root, 'System32', 'drivers', 'iida-mcp-ioctl.sys')
    # PowerShell command. Use single-quoted strings to avoid quoting hell.
    ps_cmd = (
        "$ErrorActionPreference='Continue';"
        f"sc.exe stop {SERVICE_NAME} 2>&1 | Out-Null;"
        f"sc.exe delete {SERVICE_NAME} 2>&1 | Out-Null;"
        f"Copy-Item -Force -LiteralPath '{sys_path}' -Destination '{dst}';"
        f"sc.exe create {SERVICE_NAME} type= kernel start= demand binPath= '{dst}' | Out-Null;"
        f"sc.exe start {SERVICE_NAME} | Out-Null"
    )

    sei = _SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS
    sei.lpVerb = 'runas'
    sei.lpFile = 'powershell.exe'
    sei.lpParameters = f'-NoProfile -WindowStyle Hidden -Command "{ps_cmd}"'
    sei.nShow = 0  # SW_HIDE

    shell32 = ctypes.windll.shell32
    shell32.ShellExecuteExW.argtypes = [ctypes.POINTER(_SHELLEXECUTEINFOW)]
    shell32.ShellExecuteExW.restype = wintypes.BOOL
    if not shell32.ShellExecuteExW(ctypes.byref(sei)):
        return False, f'ShellExecuteExW failed: {ctypes.get_last_error()}'
    if not sei.hProcess:
        return False, 'UAC cancelled'

    kernel32 = ctypes.windll.kernel32
    kernel32.WaitForSingleObject(sei.hProcess, 30000)
    kernel32.CloseHandle(sei.hProcess)
    return is_driver_running(), 'install completed'


def ensure_driver_loaded():
    """Returns (ok: bool, message: str). Idempotent."""
    if is_driver_running():
        return True, 'already running'
    sys_path = _find_sys()
    if not sys_path:
        return False, 'iida-mcp-ioctl.sys not found near plugin (drop the signed .sys next to iida.py)'
    ok, msg = _install_and_start(sys_path)
    if ok:
        return True, f'installed from {sys_path}'
    return False, f'install failed: {msg}'

"""iida-mcp plugin - Exposes IDA's static analysis capabilities via MCP protocol.
Supports multiple IDA instances auto-networking on port 13897.
"""
import os
import sys
import hashlib
import threading

import idaapi
import ida_nalt
import ida_ida
import ida_idaapi
import ida_kernwin
import ida_funcs
import ida_segment

# Ensure our package is importable
PLUGIN_DIR = os.path.dirname(os.path.abspath(__file__))
if PLUGIN_DIR not in sys.path:
    sys.path.insert(0, PLUGIN_DIR)


class _SuppressDialogs(ida_kernwin.UI_Hooks):
    """Auto-dismiss all modal dialogs/warnings to prevent MCP from blocking.
    Always answers YES/OK to any question IDA asks."""

    def ask_yn(self, deflt, fmt):
        return 1  # ASKBTN_YES

    def ask_buttons(self, yes_text, no_text, cancel_text, deflt, fmt):
        return 1  # first button (YES/OK)


_dialog_suppressor = None


def _get_file_id():
    """Generate stable 8-char file_id from IDB path (the .i64/.idb file, truly unique)."""
    idb_path = idaapi.get_path(idaapi.PATH_TYPE_IDB)
    h = hashlib.sha256(idb_path.encode('utf-8')).hexdigest()[:8]
    return h


def _get_file_info():
    """Collect current file metadata."""
    is64 = ida_ida.inf_is_64bit()
    is32 = ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else not is64
    return {
        'fid': _get_file_id(),
        'name': os.path.basename(ida_nalt.get_input_file_path()),
        'arch': ida_ida.inf_get_procname().strip(),
        'bits': 64 if is64 else (32 if is32 else 16),
        'path': ida_nalt.get_input_file_path(),
        'idb': idaapi.get_path(idaapi.PATH_TYPE_IDB)
    }


class IdaMcpPlugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_MULTI
    comment = "iida-mcp"
    help = ""
    wanted_name = "iida-mcp"
    wanted_hotkey = "Alt-Shift-I"

    def init(self):
        return IdaMcpPlugMod()

    def term(self):
        pass

    def run(self, arg):
        pass


class IdaMcpPlugMod(idaapi.plugmod_t):
    def __init__(self):
        super().__init__()
        self._server = None
        self._worker = None
        self._started = False

    def run(self, arg):
        """Called when user clicks iida-mcp in Edit>Plugins."""
        if self._started:
            ida_kernwin.msg("[iida-mcp] Stopping current instance...\n")
            self._cleanup()
            ida_kernwin.msg("[iida-mcp] Stopped\n")
            return
        self._started = True

        global _dialog_suppressor
        if _dialog_suppressor is None:
            _dialog_suppressor = _SuppressDialogs()
            _dialog_suppressor.hook()

        ida_kernwin.msg("[iida-mcp] Activating...\n")
        threading.Thread(target=self._init_network, daemon=True).start()

    def _show_status(self):
        if self._server:
            from iida_core.server import MCP_PORT
            entries = self._server.registry.list_all()
            names = ', '.join(e.name for e in entries)
            ida_kernwin.msg(f"[iida-mcp] Master :{MCP_PORT} | files: {names}\n")
        elif self._worker:
            if self._worker.is_promoted():
                from iida_core.server import MCP_PORT
                srv = self._worker.get_master_server()
                entries = srv.registry.list_all() if srv else []
                names = ', '.join(e.name for e in entries)
                ida_kernwin.msg(f"[iida-mcp] Promoted Master :{MCP_PORT} | files: {names}\n")
            else:
                ida_kernwin.msg("[iida-mcp] Worker connected\n")
        else:
            ida_kernwin.msg("[iida-mcp] Not connected\n")

    def _init_network(self):
        # Force-reload iida_core submodules so edits to *.py take effect on
        # Alt+Shift+I restart without quitting IDA. Order matters: leaves first.
        import importlib
        import sys
        for _name in (
            'iida_core.thread_safe',
            'iida_core.protocol',
            'iida_core.registry',
            'iida_core.cache',
            'iida_core.kdriver',
            'iida_core.driver_loader',
            'iida_core.router',
            'iida_core.worker',
            'iida_core.server',
            'iida_core.tools',
        ):
            mod = sys.modules.get(_name)
            if mod is not None:
                try:
                    importlib.reload(mod)
                except Exception as _ex:
                    ida_kernwin.msg(f"[iida-mcp] reload {_name} failed: {_ex}\n")

        from iida_core.server import McpServer, try_bind_master, MCP_PORT
        from iida_core.worker import Worker
        from iida_core.registry import FileEntry
        from iida_core import tools
        from iida_core.thread_safe import read as ida_read
        from iida_core.cache import get_cache
        from iida_core.driver_loader import ensure_driver_loaded

        # Kernel driver: auto-install via UAC if not already running.
        # Idempotent — only prompts the first time after a reboot.
        try:
            drv_ok, drv_msg = ensure_driver_loaded()
            ida_read(lambda: ida_kernwin.msg(f"[iida-mcp] kernel driver: {drv_msg}\n"))
        except Exception as ex:
            ida_read(lambda: ida_kernwin.msg(f"[iida-mcp] driver loader error: {ex}\n"))

        file_info = ida_read(_get_file_info)

        # Pre-build caches (strings, functions, names, imports, exports, segments)
        cache = get_cache()
        cache.ensure_built()

        if try_bind_master():
            self._server = McpServer(tools, tools.execute_tool)
            entry = FileEntry(
                fid=file_info['fid'],
                name=file_info['name'],
                arch=file_info['arch'],
                bits=file_info['bits'],
                path=file_info['path'],
                pid=os.getpid(),
                conn=None,
                local=True
            )
            self._server.registry.register(entry)
            self._server.start()
            bt = cache.get_build_time()
            ida_read(lambda: ida_kernwin.msg(
                f"[iida-mcp] Master on :{MCP_PORT} | {file_info['name']} ({file_info['fid']}) | cache {bt:.1f}s\n"
            ))
        else:
            self._worker = Worker(file_info, tools.execute_tool)
            self._worker.start()
            bt = cache.get_build_time()
            ida_read(lambda: ida_kernwin.msg(
                f"[iida-mcp] Worker | {file_info['name']} ({file_info['fid']}) | cache {bt:.1f}s\n"
            ))

    def __del__(self):
        self._cleanup()

    def _cleanup(self):
        if self._server:
            self._server.stop()
            self._server = None
        if self._worker:
            try:
                srv = self._worker.get_master_server()
                if srv:
                    srv.stop()
            except:
                pass
            self._worker.stop()
            self._worker = None
        self._started = False


def PLUGIN_ENTRY():
    return IdaMcpPlugin()

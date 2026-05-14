"""All MCP tool definitions and implementations for IDA static analysis."""
import os
import struct as pystruct
import hashlib
import json

import idautils
import idaapi
import ida_funcs
import ida_bytes
import ida_frame
import ida_name
import ida_nalt
import ida_segment
import ida_xref
import ida_ua
import ida_typeinf
import ida_entry
import ida_auto
import ida_gdl
import ida_lines
import ida_ida
import ida_loader
import ida_idaapi
import ida_kernwin
import idc

from .thread_safe import read, write
from .cache import get_cache

# ============================================================
# Tool schema definitions (MCP tools/list response)
# ============================================================

def _t(name, desc, params=None):
    """Helper to build tool schema entry."""
    schema = {"name": name, "description": desc}
    if params:
        schema["inputSchema"] = {
            "type": "object",
            "properties": params,
            "required": [k for k, v in params.items() if not v.get("optional")]
        }
    else:
        schema["inputSchema"] = {"type": "object", "properties": {}}
    return schema

_F = {"type": "string", "description": "file_id"}
_A = {"type": "string", "description": "hex address"}
_N = {"type": "integer", "description": "count", "optional": True}
_Q = {"type": "string", "description": "filter query", "optional": True}
_OFF = {"type": "integer", "description": "offset for pagination", "optional": True}
_STR_PAIR = {"type": "array", "items": {"type": "string"}, "minItems": 2, "maxItems": 2}
_COMMENT_ITEM = {
    "type": "array",
    "items": {"anyOf": [{"type": "string"}, {"type": "integer"}]},
    "minItems": 2,
    "maxItems": 3,
}
_BATCH_OP = {
    "type": "array",
    "items": {"anyOf": [{"type": "string"}, {"type": "object"}]},
    "minItems": 2,
    "maxItems": 2,
}

TOOLS_SCHEMA = [
    _t("list_files", "List connected IDA instances"),
    _t("get_info", "IDB info: arch, bits, entry, size, filename", {"f": _F}),
    _t("read_file_bytes", "Read raw original file bytes at file offset", {"f": _F, "off": {"type":"integer","description":"file offset"}, "sz": {"type":"integer","description":"size"}}),
    _t("addr_to_fileoff", "Convert IDB address to raw file offset", {"f": _F, "a": _A}),
    _t("get_filepath", "Get original file path on disk", {"f": _F}),
    _t("parse_pe", "Parse PE header from raw file", {"f": _F}),
    _t("parse_elf", "Parse ELF header from raw file", {"f": _F}),
    _t("list_functions", "List functions (paginated, filterable)", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("get_func_info", "Get function info: name, start, end, size, frame", {"f": _F, "a": _A}),
    _t("decompile", "Decompile function to pseudocode", {"f": _F, "a": _A}),
    _t("get_func_type", "Get function prototype/type declaration", {"f": _F, "a": _A}),
    _t("get_callers", "List functions that call this address", {"f": _F, "a": _A}),
    _t("get_callees", "List functions called by this function", {"f": _F, "a": _A}),
    _t("get_local_vars", "List decompiled function local variables", {"f": _F, "a": _A}),
    _t("get_func_args", "List decompiled function arguments", {"f": _F, "a": _A}),
    _t("disassemble", "Disassemble N instructions at address", {"f": _F, "a": _A, "n": _N}),
    _t("read_bytes", "Read bytes from IDB at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}}),
    _t("write_bytes", "Write bytes to IDB at address", {"f": _F, "a": _A, "hex": {"type":"string","description":"hex bytes"}}),
    _t("get_head", "Get item head address containing the given address", {"f": _F, "a": _A}),
    _t("get_name", "Get name/label at address", {"f": _F, "a": _A}),
    _t("set_name", "Set name/label at address", {"f": _F, "a": _A, "name": {"type":"string","description":"new name"}}),
    _t("get_comment", "Get comment at address", {"f": _F, "a": _A, "rep": {"type":"integer","description":"1=repeatable","optional":True}}),
    _t("set_comment", "Set comment at address", {"f": _F, "a": _A, "cmt": {"type":"string","description":"comment text"}, "rep": {"type":"integer","description":"1=repeatable","optional":True}}),
    _t("search_names", "Search all names/labels by substring", {"f": _F, "q": {"type":"string","description":"substring"}, "n": _N}),
    _t("get_type", "Get type info at address", {"f": _F, "a": _A}),
    _t("set_type", "Apply C type declaration at address", {"f": _F, "a": _A, "decl": {"type":"string","description":"C type declaration"}}),
    _t("list_structs", "List struct types", {"f": _F, "q": _Q}),
    _t("get_struct", "Get struct definition by name", {"f": _F, "name": {"type":"string","description":"struct name"}}),
    _t("get_struct_details", "Get struct declaration plus member list with offsets/types/comments. Use this when get_struct omits enum/type detail.", {"f": _F, "name": {"type":"string","description":"struct name"}}),
    _t("read_struct", "Read memory as an IDA struct and parse fields. source=idb reads IDB bytes, source=kernel reads runtime kernel memory.", {"f": _F, "name": {"type":"string","description":"struct name"}, "a": _A, "source": {"type":"string","description":"idb/kernel (default idb)","optional":True}, "enums": {"type":"integer","description":"include enum candidates for integer fields (default 1)","optional":True}}),
    _t("set_struct", "Create or update struct from C declaration", {"f": _F, "decl": {"type":"string","description":"C struct declaration"}}),
    _t("delete_struct", "Delete struct by name", {"f": _F, "name": {"type":"string","description":"struct name"}}),
    _t("list_enums", "List enum types", {"f": _F, "q": _Q}),
    _t("get_enum", "Get enum definition by name", {"f": _F, "name": {"type":"string","description":"enum name"}}),
    _t("find_enum_value", "Find enum constants matching a numeric value, including bitmask flag candidates.", {"f": _F, "val": {"type":"string","description":"numeric value, e.g. 3 or 0x15F0"}, "q": {"type":"string","description":"optional enum/name substring filter","optional":True}, "n": _N}),
    _t("set_enum", "Create or update enum from C declaration", {"f": _F, "decl": {"type":"string","description":"C enum declaration"}}),
    _t("list_local_types", "List all local types in type library", {"f": _F, "q": _Q}),
    _t("get_local_type", "Get local type by ordinal number", {"f": _F, "ord": {"type":"integer","description":"ordinal"}}),
    _t("set_local_type", "Add local type from C declaration", {"f": _F, "decl": {"type":"string","description":"C declaration"}}),
    _t("list_segments", "List all segments/sections", {"f": _F}),
    _t("get_segment_info", "Get segment info for address", {"f": _F, "a": _A}),
    _t("xrefs_to", "Get all cross-references TO this address", {"f": _F, "a": _A}),
    _t("xrefs_from", "Get all cross-references FROM this address", {"f": _F, "a": _A}),
    _t("search_bytes", "Search for byte pattern (e.g. '48 8B ?? 90')", {"f": _F, "pat": {"type":"string","description":"hex pattern with ?? wildcards"}, "start": {"type":"string","description":"start addr","optional":True}, "dir": {"type":"integer","description":"1=down 0=up","optional":True}}),
    _t("search_strings", "Search string list by substring", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("search_imm", "Search little-endian encoded immediate/value bytes using minimal width (1/2/4/8). Example val=15F0 searches F0 15.", {"f": _F, "val": {"type":"string","description":"hex value string, e.g. 15F0 or 0x15F0"}}),
    _t("list_imports", "List import table", {"f": _F}),
    _t("list_exports", "List export table", {"f": _F}),
    _t("list_entries", "List entry points", {"f": _F}),
    _t("get_cfg", "Get function control flow graph (nodes + edges)", {"f": _F, "a": _A}),
    _t("get_predecessors", "Get predecessor basic blocks", {"f": _F, "a": _A}),
    _t("get_successors", "Get successor basic blocks", {"f": _F, "a": _A}),
    _t("patch_bytes", "Patch bytes in IDB at address (modifies database)", {"f": _F, "a": _A, "hex": {"type":"string","description":"hex bytes to write"}}),
    _t("patch_list", "List all patched bytes in IDB", {"f": _F}),
    _t("bookmark_list", "List all bookmarks", {"f": _F}),
    _t("bookmark_set", "Set bookmark at address", {"f": _F, "a": _A, "desc": {"type":"string","description":"description"}}),
    _t("bookmark_delete", "Delete bookmark at address", {"f": _F, "a": _A}),
    _t("reanalyze", "Trigger IDA auto-analysis and wait", {"f": _F}),
    _t("create_function", "Create function at address", {"f": _F, "a": _A, "end": {"type":"string","description":"end addr","optional":True}}),
    _t("delete_function", "Delete function at address", {"f": _F, "a": _A}),
    _t("make_data", "Define data at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}, "type": {"type":"string","description":"byte/word/dword/qword","optional":True}}),
    _t("undefine", "Undefine (make unknown) bytes at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"size"}}),
    _t("rename_var", "Rename a decompiled local variable", {"f": _F, "a": _A, "old": {"type":"string","description":"old name"}, "new": {"type":"string","description":"new name"}}),
    _t("retype_var", "Change type of a decompiled variable", {"f": _F, "a": _A, "var": {"type":"string","description":"var name"}, "decl": {"type":"string","description":"C type"}}),
    _t("batch", "Batch execute multiple tools in one call", {"f": {"type":"string","description":"default file_id","optional":True}, "ops": {"type":"array","description":"[[tool_name,{args}],...]","items":_BATCH_OP}}),
    _t("batch_set_names", "Batch rename: set names at multiple addresses in one call", {"f": _F, "names": {"type":"array","description":"[[hex_addr, name], ...]","items":_STR_PAIR}}),
    _t("batch_set_comments", "Batch comment: set comments at multiple addresses in one call", {"f": _F, "comments": {"type":"array","description":"[[hex_addr, text, rep?], ...]","items":_COMMENT_ITEM}}),
    _t("batch_set_types", "Batch set types at multiple addresses in one call", {"f": _F, "types": {"type":"array","description":"[[hex_addr, c_decl], ...]","items":_STR_PAIR}}),
    _t("batch_decompile", "Decompile multiple functions in one call", {"f": _F, "addrs": {"type":"array","description":"[hex_addr, ...]","items":{"type":"string"}}}),
    _t("get_func_by_addr", "Find which function contains the given address (any addr, not just func start)", {"f": _F, "a": _A}),
    _t("call_tree", "Build forward call tree (recursive callees from function)", {"f": _F, "a": _A, "depth": {"type":"integer","description":"max depth (default 5)","optional":True}}),
    _t("callers_tree", "Build reverse call tree (recursive callers of function)", {"f": _F, "a": _A, "depth": {"type":"integer","description":"max depth (default 5)","optional":True}}),
    _t("kernel_read", "Read kernel memory via iida-mcp-ioctl driver (SEH protected). Returns hex string of bytes.", {"a": {"type":"string","description":"kernel virtual address (hex, e.g. fffff80455740000)"}, "sz": {"type":"integer","description":"size in bytes (max 65536)"}}),
    _t("kernel_modules", "List all loaded kernel modules via driver. Returns [[base_hex, size, name, path], ...]"),
    _t("kernel_module_base", "Get kernel module base address and size by name via driver. Returns [base_hex, size]", {"name": {"type":"string","description":"module name, e.g. ntoskrnl or nvlddmkm"}}),
    _t("calc", "Integer calculator. Evaluate arithmetic expression with hex(0x)/dec/oct(0o)/bin(0b). Supports + - * / % ** << >> & | ^ ~. Returns [dec, hex]", {"expr": {"type":"string","description":"expression, e.g. 0xfffff804+0x1000*3"}}),
    _t("disasm_bytes", "Disassemble raw hex bytes (no IDB needed). Returns [[offset, hex, mnemonic, operands], ...]", {"hex": {"type":"string","description":"hex bytes, e.g. 4889e5 or 48 89 e5"}, "arch": {"type":"string","description":"x86/x64/arm/arm64 (default x64)","optional":True}, "addr": {"type":"string","description":"base address for display (default 0)","optional":True}}),
    _t("kernel_read_values", "Read kernel memory and interpret as typed values. Use a for one address or addrs for batch. fmt defaults to p(pointer).", {"a": {"type":"string","description":"single kernel virtual address (hex)","optional":True}, "addrs": {"type":"array","description":"batch kernel virtual addresses [hex_addr, ...]","items":{"type":"string"},"optional":True}, "fmt": {"type":"string","description":"format: p(pointer/u64) d(u32) w(u16) b(u8) s(null-term string) or NNx(raw bytes). e.g. p, ppd, 16x. default p","optional":True}}),
    _t("ida_to_runtime", "Convert IDA virtual address to runtime kernel address. Uses runtime module base from driver + IDA segment info to compute correct mapping per-section.", {"f": _F, "a": _A, "mod": {"type":"string","description":"kernel module name (e.g. nvlddmkm)","optional":True}}),

    # --- mrexodia/ida-pro-mcp parity tools ---
    _t("check_connection", "Ping the MCP server"),
    _t("get_metadata", "Alias of get_info: IDB metadata", {"f": _F}),
    _t("get_current_address", "Get IDA UI screen cursor address", {"f": _F}),
    _t("get_current_function", "Get function at IDA UI screen cursor", {"f": _F}),
    _t("get_function_by_name", "Find function address by exact name", {"f": _F, "name": {"type":"string","description":"function name"}}),
    _t("get_function_by_address", "Alias of get_func_info", {"f": _F, "a": _A}),
    _t("convert_number", "Alias of calc: evaluate numeric expression", {"expr": {"type":"string","description":"expression"}}),
    _t("list_functions_filter", "Alias of list_functions with filter", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("list_strings", "Alias of search_strings (no filter)", {"f": _F, "off": _OFF, "n": _N}),
    _t("list_strings_filter", "Alias of search_strings with filter", {"f": _F, "q": _Q, "off": _OFF, "n": _N}),
    _t("decompile_function", "Alias of decompile", {"f": _F, "a": _A}),
    _t("disassemble_function", "Alias of disassemble", {"f": _F, "a": _A, "n": _N}),
    _t("get_xrefs_to", "Alias of xrefs_to", {"f": _F, "a": _A}),
    _t("get_xrefs_to_field", "Cross-references to a struct field by name", {"f": _F, "struct": {"type":"string","description":"struct name"}, "field": {"type":"string","description":"field name"}}),
    _t("get_entry_points", "Alias of list_entries", {"f": _F}),
    _t("rename_local_variable", "Alias of rename_var", {"f": _F, "a": _A, "old": {"type":"string"}, "new": {"type":"string"}}),
    _t("rename_global_variable", "Alias of set_name (rename data label)", {"f": _F, "a": _A, "name": {"type":"string"}}),
    _t("set_global_variable_type", "Alias of set_type for global var", {"f": _F, "a": _A, "decl": {"type":"string"}}),
    _t("rename_function", "Alias of set_name for a function", {"f": _F, "a": _A, "name": {"type":"string"}}),
    _t("set_local_variable_type", "Alias of retype_var", {"f": _F, "a": _A, "var": {"type":"string"}, "decl": {"type":"string"}}),
    _t("get_defined_structures", "Alias of list_structs", {"f": _F, "q": _Q}),
    _t("analyze_struct_detailed", "Alias of get_struct_details", {"f": _F, "name": {"type":"string"}}),
    _t("get_struct_at_address", "Identify which struct type is applied at an address", {"f": _F, "a": _A}),
    _t("get_struct_info_simple", "Alias of get_struct", {"f": _F, "name": {"type":"string"}}),
    _t("search_structures", "Alias of list_structs with filter", {"f": _F, "q": _Q}),
    _t("read_memory_bytes", "Alias of read_bytes", {"f": _F, "a": _A, "sz": {"type":"integer"}}),
    _t("data_read_byte", "Read 1 byte at address (returns [dec, hex])", {"f": _F, "a": _A}),
    _t("data_read_word", "Read 2 bytes (word) at address (returns [dec, hex])", {"f": _F, "a": _A}),
    _t("data_read_dword", "Read 4 bytes (dword) at address (returns [dec, hex])", {"f": _F, "a": _A}),
    _t("data_read_qword", "Read 8 bytes (qword) at address (returns [dec, hex])", {"f": _F, "a": _A}),
    _t("data_read_string", "Read string literal at address (auto/strtype, default C string)", {"f": _F, "a": _A, "strtype": {"type":"integer","description":"IDA STRTYPE_* constant; -1=default","optional":True}, "max": {"type":"integer","description":"max bytes (default 4096)","optional":True}}),
    _t("declare_c_type", "Declare a new C type/typedef/struct via parse_decls (adds to local types)", {"f": _F, "decl": {"type":"string","description":"C declarations"}}),
    _t("set_function_prototype", "Apply a C function prototype at function address", {"f": _F, "a": _A, "decl": {"type":"string","description":"function prototype, e.g. 'int __fastcall foo(int a, char *b)'"}}),
    _t("patch_address_assembles", "Assemble an instruction with keystone and patch at address. Auto-detects arch.", {"f": _F, "a": _A, "asm": {"type":"string","description":"assembly text, e.g. 'mov rax, 1'"}}),
    _t("get_global_variable_value_by_name", "Read a global variable value by name", {"f": _F, "name": {"type":"string"}, "sz": {"type":"integer","description":"override size","optional":True}}),
    _t("get_global_variable_value_at_address", "Read a global variable value at address", {"f": _F, "a": _A, "sz": {"type":"integer","description":"override size","optional":True}}),
    _t("list_globals", "List named non-function globals (paginated, filterable)", {"f": _F, "q": _Q, "n": _N}),
    _t("list_globals_filter", "Alias of list_globals", {"f": _F, "q": _Q, "n": _N}),
    _t("get_stack_frame_variables", "List a function's stack frame variables: [offset, size, name, type]", {"f": _F, "a": _A}),
    _t("create_stack_frame_variable", "Create a stack frame variable at offset", {"f": _F, "a": _A, "name": {"type":"string"}, "offset": {"type":"integer","description":"byte offset in frame"}, "decl": {"type":"string","description":"C type (default unsigned char)","optional":True}}),
    _t("delete_stack_frame_variable", "Delete a stack frame variable by name", {"f": _F, "a": _A, "name": {"type":"string"}}),
    _t("rename_stack_frame_variable", "Rename a stack frame variable", {"f": _F, "a": _A, "old": {"type":"string"}, "new": {"type":"string"}}),
    _t("set_stack_frame_variable_type", "Set type of a stack frame variable", {"f": _F, "a": _A, "name": {"type":"string"}, "decl": {"type":"string","description":"C type"}}),
]


# ============================================================
# Tool implementations
# ============================================================

def _ea(s):
    """Parse hex address string to int."""
    if isinstance(s, int):
        return s
    return int(s, 16)


def _hex(val):
    """Int to hex string without 0x prefix."""
    return format(val, 'x')


def _pt_sil():
    return getattr(ida_typeinf, 'PT_SIL', getattr(idc, 'PT_SIL', 0))


def _ntf_replace():
    return getattr(ida_typeinf, 'NTF_REPLACE', getattr(idc, 'NTF_REPLACE', 1))


def _tinfo_present(tif):
    try:
        return tif.present()
    except:
        try:
            return not tif.empty()
        except:
            return False


def _parse_tinfo_decl(tif, til, decl):
    """Parse a C declaration across IDA 8.x/9.x return-value differences."""
    try:
        r = ida_typeinf.parse_decl(tif, til, decl, _pt_sil())
        return bool(r) or _tinfo_present(tif)
    except TypeError:
        pass
    try:
        return bool(tif.parse(decl, til, _pt_sil())) or _tinfo_present(tif)
    except:
        return False


def _apply_tinfo(ea, tif):
    flags = getattr(ida_typeinf, 'TINFO_DEFINITE', getattr(idaapi, 'TINFO_DEFINITE', 0))
    for mod in (idaapi, ida_typeinf):
        fn = getattr(mod, 'apply_tinfo', None)
        if fn:
            try:
                if fn(ea, tif, flags):
                    return True
            except:
                pass
    return False


def _apply_type_decl(ea, decl):
    try:
        if idc.SetType(ea, decl):
            return True
    except:
        pass
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if _parse_tinfo_decl(tif, til, decl):
        return _apply_tinfo(ea, tif)
    return False


def _type_ordinal_by_name(til, name):
    if not name:
        return 0
    try:
        ordinal = ida_typeinf.get_type_ordinal(til, name)
        if ordinal:
            return ordinal
    except:
        pass
    try:
        limit = idc.get_ordinal_limit()
    except:
        try:
            limit = ida_typeinf.get_ordinal_qty(til) + 1
        except:
            limit = 0
    for ordinal in range(1, limit):
        try:
            if idc.get_numbered_type_name(ordinal) == name:
                return ordinal
        except:
            pass
    return 0


def _local_type_ordinals(til):
    try:
        limit = ida_typeinf.get_ordinal_qty(til) + 1
        return range(1, limit)
    except:
        pass
    try:
        limit = idc.get_ordinal_limit()
        return range(1, limit)
    except:
        return range(1, 0)


def _save_local_type_decl(decl):
    """Create/update a named local type in a way that works on IDA 8.3 and 9.x."""
    try:
        ordinal = idc.set_local_type(-1, decl, _pt_sil())
        if ordinal:
            return ordinal
    except:
        pass

    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not _parse_tinfo_decl(tif, til, decl):
        return 0
    name = tif.get_type_name()
    if not name:
        return 0

    for saver in ('set_named_type', 'save_type'):
        fn = getattr(tif, saver, None)
        if not fn:
            continue
        try:
            if saver == 'set_named_type':
                fn(til, name, _ntf_replace())
            else:
                fn(_ntf_replace())
            ordinal = _type_ordinal_by_name(til, name)
            if ordinal:
                return ordinal
        except:
            pass

    try:
        ordinal = _type_ordinal_by_name(til, name) or ida_typeinf.alloc_type_ordinal(til)
        tif.set_numbered_type(til, ordinal, _ntf_replace(), name)
        return _type_ordinal_by_name(til, name) or ordinal
    except:
        return 0


def _delete_local_type(name):
    til = ida_typeinf.get_idati()
    ordinal = _type_ordinal_by_name(til, name)
    if not ordinal:
        return 'not found'
    try:
        ida_typeinf.del_numbered_type(til, ordinal)
    except:
        try:
            idc.set_local_type(ordinal, '', 0)
        except:
            return 'fail'
    return 'ok' if not _type_ordinal_by_name(til, name) else 'fail'


def _block_succs(block):
    try:
        return list(block.succs())
    except:
        pass
    try:
        return [block.succ(i) for i in range(block.nsucc())]
    except:
        return []


def _block_preds(block):
    try:
        return list(block.preds())
    except:
        pass
    try:
        return [block.pred(i) for i in range(block.npred())]
    except:
        return []


def _addr_ctx(ea):
    """Get context for an address: (func_name, comment). Runs on IDA main thread."""
    func = ida_funcs.get_func(ea)
    fname = ida_funcs.get_func_name(func.start_ea) if func else ''
    cmt = ida_bytes.get_cmt(ea, 0) or ida_bytes.get_cmt(ea, 1) or ''
    return fname, cmt


def _bin_search_ea(result):
    if isinstance(result, tuple):
        result = result[0]
    return result


def _get_input_path():
    return ida_nalt.get_input_file_path()


# --- 4.1 Meta & File ---

def _info(args):
    def _impl():
        procname = ida_ida.inf_get_procname()
        is64 = ida_ida.inf_is_64bit()
        is32 = ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else not is64
        return {
            'proc': procname,
            'bits': 64 if is64 else (32 if is32 else 16),
            'entry': _hex(ida_ida.inf_get_start_ea()),
            'min': _hex(ida_ida.inf_get_min_ea()),
            'max': _hex(ida_ida.inf_get_max_ea()),
            'segs': ida_segment.get_segm_qty(),
            'funcs': ida_funcs.get_func_qty(),
            'type': ida_loader.get_file_type_name(),
            'compiler': ida_ida.inf_get_cc_id()
        }
    return read(_impl)


def _fraw(args):
    off = args.get('off', 0)
    sz = min(args.get('sz', 256), 0x100000)  # cap at 1MB
    path = read(_get_input_path)
    with open(path, 'rb') as fp:
        fp.seek(off)
        data = fp.read(sz)
    return data.hex()


def _fmap(args):
    ea = _ea(args['a'])
    def _impl():
        return ida_loader.get_fileregion_offset(ea)
    offset = read(_impl)
    return offset if offset != -1 else None


def _fpath(args):
    return read(_get_input_path)


# --- 4.2 PE/ELF ---

def _pe(args):
    path = read(_get_input_path)
    with open(path, 'rb') as fp:
        dos = fp.read(64)
        if dos[:2] != b'MZ':
            return {'e': 'not PE'}
        pe_off = pystruct.unpack_from('<I', dos, 60)[0]
        fp.seek(pe_off)
        sig = fp.read(4)
        if sig != b'PE\x00\x00':
            return {'e': 'bad PE sig'}
        coff = fp.read(20)
        machine, nsections, timestamp = pystruct.unpack_from('<HHI', coff, 0)
        opt_size = pystruct.unpack_from('<H', coff, 16)[0]
        opt = fp.read(opt_size)
        magic = pystruct.unpack_from('<H', opt, 0)[0]
        is64 = magic == 0x20b
        if is64:
            entry = pystruct.unpack_from('<I', opt, 16)[0]
            image_base = pystruct.unpack_from('<Q', opt, 24)[0]
            subsystem = pystruct.unpack_from('<H', opt, 68)[0]
            nrva = pystruct.unpack_from('<I', opt, 108)[0]
        else:
            entry = pystruct.unpack_from('<I', opt, 16)[0]
            image_base = pystruct.unpack_from('<I', opt, 28)[0]
            subsystem = pystruct.unpack_from('<H', opt, 68)[0]
            nrva = pystruct.unpack_from('<I', opt, 92)[0]

        sections = []
        for _ in range(nsections):
            shdr = fp.read(40)
            sname = shdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
            vsize, vaddr, rawsz, rawoff = pystruct.unpack_from('<IIII', shdr, 8)
            chars = pystruct.unpack_from('<I', shdr, 36)[0]
            sections.append([sname, _hex(vaddr), vsize, rawsz, rawoff, chars])

        return {
            'machine': machine,
            'timestamp': timestamp,
            'image_base': _hex(image_base),
            'entry': _hex(entry),
            'subsystem': subsystem,
            'is64': is64,
            'sections': sections
        }


def _elf(args):
    path = read(_get_input_path)
    with open(path, 'rb') as fp:
        ident = fp.read(16)
        if ident[:4] != b'\x7fELF':
            return {'e': 'not ELF'}
        ei_class = ident[4]  # 1=32, 2=64
        ei_data = ident[5]   # 1=LE, 2=BE
        endian = '<' if ei_data == 1 else '>'
        is64 = ei_class == 2

        if is64:
            hdr = fp.read(48)
            etype, machine = pystruct.unpack_from(endian + 'HH', hdr, 0)
            entry = pystruct.unpack_from(endian + 'Q', hdr, 8)[0]
            phoff = pystruct.unpack_from(endian + 'Q', hdr, 16)[0]
            shoff = pystruct.unpack_from(endian + 'Q', hdr, 24)[0]
            phnum = pystruct.unpack_from(endian + 'H', hdr, 40)[0]
            shnum = pystruct.unpack_from(endian + 'H', hdr, 44)[0]
        else:
            hdr = fp.read(36)
            etype, machine = pystruct.unpack_from(endian + 'HH', hdr, 0)
            entry = pystruct.unpack_from(endian + 'I', hdr, 8)[0]
            phoff = pystruct.unpack_from(endian + 'I', hdr, 12)[0]
            shoff = pystruct.unpack_from(endian + 'I', hdr, 16)[0]
            phnum = pystruct.unpack_from(endian + 'H', hdr, 28)[0]
            shnum = pystruct.unpack_from(endian + 'H', hdr, 30)[0]

        phdrs = []
        if phoff:
            fp.seek(phoff)
            for _ in range(min(phnum, 64)):
                if is64:
                    p = fp.read(56)
                    ptype, pflags = pystruct.unpack_from(endian + 'II', p, 0)
                    poff, pvaddr, pmemsz = pystruct.unpack_from(endian + 'QQQ', p, 8)[:3]
                    phdrs.append([ptype, _hex(pvaddr), pmemsz, pflags])
                else:
                    p = fp.read(32)
                    ptype = pystruct.unpack_from(endian + 'I', p, 0)[0]
                    poff, pvaddr = pystruct.unpack_from(endian + 'II', p, 4)
                    pmemsz = pystruct.unpack_from(endian + 'I', p, 20)[0]
                    pflags = pystruct.unpack_from(endian + 'I', p, 24)[0]
                    phdrs.append([ptype, _hex(pvaddr), pmemsz, pflags])

        return {
            'class': ei_class,
            'machine': machine,
            'entry': _hex(entry),
            'type': etype,
            'phdr': phdrs,
            'shnum': shnum
        }


# --- 4.3 Functions ---

def _fl(args):
    q = args.get('q', '')
    off = args.get('off', 0)
    n = min(args.get('n', 100), 1000)
    cache = get_cache()
    data = cache.get_functions(q, off, n)
    eas = [ea for ea, _, _ in data]
    def _get_comments(addrs=eas):
        return {a: (ida_bytes.get_cmt(a, 0) or ida_bytes.get_cmt(a, 1) or '') for a in addrs}
    cmts = read(_get_comments) if eas else {}
    results = []
    for ea, name, sz in data:
        row = [_hex(ea), name, sz]
        c = cmts.get(ea, '')
        if c:
            row.append(c)
        results.append(row)
    return results


def _fi(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        tif = ida_typeinf.tinfo_t()
        ida_typeinf.guess_tinfo(tif, ea)
        frame_size = ida_frame.get_frame_size(func) if func.frame != idaapi.BADADDR else 0
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size(),
            func.flags,
            frame_size,
            func.frsize,
            func.argsize,
            str(tif) if tif.present() else ''
        ]
    return read(_impl)


def _dec(args):
    ea = _ea(args['a'])
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if cfunc:
                lines = cfunc.get_pseudocode()
                text = '\n'.join(ida_lines.tag_remove(l.line) for l in lines)
                return text
            return {'e': 'decompile failed'}
        except Exception as ex:
            return {'e': str(ex)}
    return read(_impl)


def _decl(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        # Prefer precise tinfo (honors user-set prototype); fall back to guess.
        if idaapi.get_tinfo(tif, ea) or ida_typeinf.guess_tinfo(tif, ea):
            name = ida_funcs.get_func_name(ea) or ''
            return tif.dstr() if not name else str(tif) + ' ' + name
        return ''
    return read(_impl)


def _cf(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.CodeRefsTo(ea, 0):
            fn = ida_funcs.get_func(xref)
            fname = ida_funcs.get_func_name(fn.start_ea) if fn else ''
            cmt = ida_bytes.get_cmt(fn.start_ea, 0) or ida_bytes.get_cmt(fn.start_ea, 1) or '' if fn else ''
            row = [_hex(xref), fname]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


def _ct(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        seen = set()
        results = []
        for item_ea in idautils.FuncItems(func.start_ea):
            for xref in idautils.CodeRefsFrom(item_ea, 0):
                fn = ida_funcs.get_func(xref)
                if fn and fn.start_ea != func.start_ea and fn.start_ea not in seen:
                    seen.add(fn.start_ea)
                    name = ida_funcs.get_func_name(fn.start_ea) or ''
                    cmt = ida_bytes.get_cmt(fn.start_ea, 0) or ida_bytes.get_cmt(fn.start_ea, 1) or ''
                    row = [_hex(fn.start_ea), name]
                    if cmt:
                        row.append(cmt)
                    results.append(row)
        return results
    return read(_impl)


def _fv(args):
    ea = _ea(args['a'])
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return []
            results = []
            for v in cfunc.lvars:
                if not v.is_arg_var:
                    results.append([v.name, str(v.tif), v.location.stkoff() if v.is_stk_var() else -1])
            return results
        except:
            return []
    return read(_impl)


def _fa(args):
    ea = _ea(args['a'])
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return []
            results = []
            for v in cfunc.lvars:
                if v.is_arg_var:
                    results.append([v.name, str(v.tif), v.location.dstr()])
            return results
        except:
            return []
    return read(_impl)


# --- 4.4 Disassembly & Bytes ---

def _dis(args):
    ea = _ea(args['a'])
    n = min(args.get('n', 32), 512)
    def _impl():
        results = []
        cur = ea
        for _ in range(n):
            sz = ida_bytes.get_item_size(cur)
            if sz == 0:
                break
            raw = ida_bytes.get_bytes(cur, sz)
            insn = ida_ua.insn_t()
            cmt = ida_bytes.get_cmt(cur, 0) or ida_bytes.get_cmt(cur, 1) or ''
            if ida_ua.decode_insn(insn, cur) > 0:
                mnem = insn.get_canon_mnem()
                ops = ida_lines.tag_remove(idc.GetDisasm(cur))
                ops_part = ops[len(mnem):].strip() if ops.startswith(mnem) else ops
                row = [_hex(cur), raw.hex() if raw else '', mnem, ops_part]
            else:
                row = [_hex(cur), raw.hex() if raw else '', 'db', '']
            if cmt:
                row.append(cmt)
            results.append(row)
            cur += sz
        return results
    return read(_impl)


def _rb(args):
    ea = _ea(args['a'])
    sz = min(args.get('sz', 16), 0x100000)
    def _impl():
        data = ida_bytes.get_bytes(ea, sz)
        return data.hex() if data else ''
    return read(_impl)


def _wb(args):
    ea = _ea(args['a'])
    hexstr = args['hex']
    data = bytes.fromhex(hexstr)
    def _impl():
        ida_bytes.put_bytes(ea, data)
        return 'ok'
    return write(_impl)


def _head(args):
    ea = _ea(args['a'])
    def _impl():
        return _hex(ida_bytes.get_item_head(ea))
    return read(_impl)


# --- 4.5 Names & Comments ---

def _gn(args):
    ea = _ea(args['a'])
    def _impl():
        n = ida_name.get_name(ea)
        if n:
            demang = ida_name.demangle_name(n, 0)
            return demang if demang else n
        return ''
    return read(_impl)


def _sn(args):
    ea = _ea(args['a'])
    name = args['name']
    def _impl():
        return 'ok' if ida_name.set_name(ea, name, ida_name.SN_NOWARN) else 'fail'
    return write(_impl)


def _gc(args):
    ea = _ea(args['a'])
    rep = args.get('rep', 0)
    def _impl():
        return ida_bytes.get_cmt(ea, bool(rep)) or ''
    return read(_impl)


def _sc(args):
    ea = _ea(args['a'])
    cmt = args['cmt']
    rep = args.get('rep', 0)
    def _impl():
        ida_bytes.set_cmt(ea, cmt, bool(rep))
        return 'ok'
    return write(_impl)


def _an(args):
    q = args['q']
    n = min(args.get('n', 50), 500)
    cache = get_cache()
    data = cache.get_names(q, n)
    return [[_hex(ea), name] for ea, name in data]


# --- 4.6 Types ---

def _gt(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        if idaapi.get_tinfo(tif, ea):
            return str(tif)
        if ida_typeinf.guess_tinfo(tif, ea):
            return str(tif)
        return ''
    return read(_impl)


def _st(args):
    ea = _ea(args['a'])
    decl = args['decl']
    def _impl():
        return 'ok' if _apply_type_decl(ea, decl) else 'fail'
    return write(_impl)


def _tl(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                if tif.is_struct():
                    name = tif.get_type_name()
                    if not q or q in name.lower():
                        results.append([name, tif.get_size()])
        return results
    return read(_impl)


def _tg(args):
    name = args['name']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(til, name):
            return tif.dstr()
        return ''
    return read(_impl)


def _struct_member_attr(member, name, default=None):
    try:
        v = getattr(member, name)
        return v() if callable(v) else v
    except:
        return default


def _struct_member_bits(member):
    for attr in ('size', 'size_bits'):
        v = _struct_member_attr(member, attr)
        if isinstance(v, int) and v >= 0:
            return v
    try:
        t = _struct_member_attr(member, 'type')
        if t:
            sz = t.get_size()
            if sz and sz > 0:
                return sz * 8
    except:
        pass
    return 0


def _struct_detail_in_ida(name):
    til = ida_typeinf.get_idati()
    tif = ida_typeinf.tinfo_t()
    if not tif.get_named_type(til, name):
        return {'e': 'not found'}

    result = {
        'name': name,
        'size': tif.get_size(),
        'decl': tif.dstr(),
        'members': []
    }

    try:
        udt = ida_typeinf.udt_type_data_t()
        if not tif.get_udt_details(udt):
            return result
        for m in udt:
            off_bits = _struct_member_attr(m, 'offset', 0) or 0
            size_bits = _struct_member_bits(m)
            mname = _struct_member_attr(m, 'name', '') or ''
            mtif = _struct_member_attr(m, 'type')
            mtype = str(mtif) if mtif else ''
            cmt = _struct_member_attr(m, 'cmt', '') or ''
            result['members'].append([
                off_bits // 8,
                size_bits // 8 if size_bits else 0,
                mname,
                mtype,
                cmt
            ])
    except Exception as ex:
        result['member_error'] = str(ex)
    return result


def _tgd(args):
    name = args['name']
    def _impl():
        return _struct_detail_in_ida(name)
    return read(_impl)


def _ts(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return 'ok' if ordinal else 'parse error'
    return write(_impl)


def _td(args):
    name = args['name']
    def _impl():
        return _delete_local_type(name)
    return write(_impl)


def _el(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                if tif.is_enum():
                    name = tif.get_type_name()
                    if not q or q in name.lower():
                        results.append([name, tif.get_size()])
        return results
    return read(_impl)


def _eg(args):
    name = args['name']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_named_type(til, name):
            return tif.dstr()
        return ''
    return read(_impl)


def _enum_eval_expr(expr, known):
    import re
    expr = expr.strip()
    expr = re.sub(r'\b([0-9A-Fa-f]+)[uUlL]+\b', r'\1', expr)
    expr = re.sub(r'\b[A-Za-z_][A-Za-z0-9_]*\b', lambda m: str(known.get(m.group(0), 0)), expr)
    if not all(c in '0123456789abcdefABCDEFxX+-*/%()<>&|^~ \t' for c in expr):
        raise ValueError('bad enum expr')
    return int(eval(compile(expr, '<enum>', 'eval'), {"__builtins__": {}}, {}))


def _enum_constants_from_decl(decl):
    import re
    body_match = re.search(r'\{(.*)\}', decl, re.S)
    if not body_match:
        return []
    body = re.sub(r'/\*.*?\*/|//.*?$', '', body_match.group(1), flags=re.S | re.M)
    parts = [p.strip() for p in body.split(',') if p.strip()]
    consts = []
    known = {}
    cur = -1
    for part in parts:
        m = re.match(r'([A-Za-z_][A-Za-z0-9_]*)(?:\s*=\s*(.*))?$', part)
        if not m:
            continue
        cname = m.group(1)
        expr = (m.group(2) or '').strip()
        try:
            cur = _enum_eval_expr(expr, known) if expr else cur + 1
        except:
            cur += 1
        known[cname] = cur
        consts.append([cname, cur])
    return consts


def _find_enum_value_in_ida(val, q='', limit=50):
    q = (q or '').lower()
    til = ida_typeinf.get_idati()
    exact = []
    flags = []
    for ordinal in _local_type_ordinals(til):
        tif = ida_typeinf.tinfo_t()
        if not tif.get_numbered_type(til, ordinal) or not tif.is_enum():
            continue
        ename = tif.get_type_name() or ''
        decl = tif.dstr()
        if q and q not in ename.lower() and q not in decl.lower():
            continue
        consts = _enum_constants_from_decl(decl)
        if not consts:
            continue

        ex = [[n, _hex(v)] for n, v in consts if v == val]
        if ex:
            exact.append([ename, ex])

        parts = [[n, _hex(v)] for n, v in consts if v and (val & v) == v]
        if parts:
            flags.append([ename, parts[:32]])

        if len(exact) + len(flags) >= limit:
            break

    return {'value': _hex(val), 'exact': exact[:limit], 'flags': flags[:limit]}


def _find_enum_value(args):
    val = _ea(args['val'])
    q = args.get('q', '').lower()
    limit = min(args.get('n', 50), 500)
    def _impl():
        return _find_enum_value_in_ida(val, q, limit)

    return read(_impl)


def _guess_field_size(mtype, msize):
    if msize:
        return msize
    t = (mtype or '').lower()
    if '*' in t or 'qword' in t or '__int64' in t or 'uint64' in t:
        return 8
    if 'dword' in t or '__int32' in t or 'uint32' in t or 'int ' in t:
        return 4
    if 'word' in t or '__int16' in t or 'uint16' in t:
        return 2
    if 'byte' in t or 'char' in t or 'bool' in t:
        return 1
    return 0


def _read_struct(args):
    name = args['name']
    ea = _ea(args['a'])
    source = args.get('source', 'idb').lower()
    include_enums = bool(args.get('enums', 1))

    detail = read(lambda: _struct_detail_in_ida(name))
    if isinstance(detail, dict) and 'e' in detail:
        return detail

    size = int(detail.get('size') or 0)
    if size <= 0:
        return {'e': 'struct has unknown size', 'struct': detail}
    if size > 0x100000:
        return {'e': 'struct too large (max 1MB)', 'size': size}

    if source == 'kernel':
        from .kdriver import read_kernel_memory
        raw = read_kernel_memory(ea, size)
        if isinstance(raw, dict):
            return raw
        data = bytes.fromhex(raw)
    elif source == 'idb':
        data = read(lambda: ida_bytes.get_bytes(ea, size))
        if not data:
            return {'e': f'no IDB bytes at {_hex(ea)}'}
    else:
        return {'e': 'source must be idb or kernel'}

    fields = []
    enum_cache = {}
    for off, msize, mname, mtype, cmt in detail.get('members', []):
        fsize = _guess_field_size(mtype, int(msize or 0))
        if fsize <= 0:
            fsize = 1
        raw = data[off:off + fsize] if off < len(data) else b''
        row = {
            'off': _hex(off),
            'size': fsize,
            'name': mname,
            'type': mtype,
            'raw': raw.hex()
        }
        if cmt:
            row['cmt'] = cmt
        if raw and fsize <= 8:
            val = int.from_bytes(raw.ljust(fsize, b'\x00'), 'little')
            row['value'] = _hex(val)
            if include_enums and val:
                q = (mtype or mname or '').replace('*', '').replace('const ', '').strip()
                key = (val, q)
                if key not in enum_cache:
                    enum_cache[key] = read(lambda v=val, qq=q: _find_enum_value_in_ida(v, qq, 8))
                    if not enum_cache[key].get('exact') and not enum_cache[key].get('flags') and q:
                        enum_cache[key] = read(lambda v=val: _find_enum_value_in_ida(v, '', 8))
                cand = enum_cache[key]
                if cand.get('exact') or cand.get('flags'):
                    row['enum'] = cand
        elif raw and ('char' in (mtype or '').lower() or fsize > 8):
            z = raw.find(b'\x00')
            preview = raw[:z if z >= 0 else min(len(raw), 64)]
            try:
                row['str'] = preview.decode('utf-8', errors='replace')
            except:
                pass
        fields.append(row)

    return {
        'addr': _hex(ea),
        'source': source,
        'struct': name,
        'size': size,
        'raw': data[:size].hex(),
        'fields': fields
    }


def _es(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return 'ok' if ordinal else 'parse error'
    return write(_impl)


def _lti(args):
    q = args.get('q', '').lower()
    def _impl():
        til = ida_typeinf.get_idati()
        results = []
        for ordinal in _local_type_ordinals(til):
            tif = ida_typeinf.tinfo_t()
            if tif.get_numbered_type(til, ordinal):
                name = tif.get_type_name()
                if name and (not q or q in name.lower()):
                    results.append([ordinal, name, tif.dstr()])
        return results
    return read(_impl)


def _ltg(args):
    ordinal = args['ord']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if tif.get_numbered_type(til, ordinal):
            return tif.dstr()
        return ''
    return read(_impl)


def _lts(args):
    decl = args['decl']
    def _impl():
        ordinal = _save_local_type_decl(decl)
        return ordinal if ordinal else 'fail'
    return write(_impl)


# --- 4.7 Segments ---

def _segs(args):
    cache = get_cache()
    data = cache.get_segments()
    return [[_hex(s), _hex(e), name, cls, perm, bits] for s, e, name, cls, perm, bits in data]


def _segi(args):
    ea = _ea(args['a'])
    def _impl():
        seg = ida_segment.getseg(ea)
        if not seg:
            return None
        return {
            'start': _hex(seg.start_ea),
            'end': _hex(seg.end_ea),
            'name': ida_segment.get_segm_name(seg),
            'cls': ida_segment.get_segm_class(seg),
            'perm': seg.perm,
            'bits': seg.bitness
        }
    return read(_impl)


# --- 4.8 Xrefs ---

def _xto(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.XrefsTo(ea, 0):
            fn, cmt = _addr_ctx(xref.frm)
            row = [_hex(xref.frm), xref.type, fn]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


def _xfrom(args):
    ea = _ea(args['a'])
    def _impl():
        results = []
        for xref in idautils.XrefsFrom(ea, 0):
            fn, cmt = _addr_ctx(xref.to)
            row = [_hex(xref.to), xref.type, fn]
            if cmt:
                row.append(cmt)
            results.append(row)
        return results
    return read(_impl)


# --- 4.9 Search ---

def _srch(args):
    pat = args['pat']
    start = _ea(args['start']) if 'start' in args else None
    direction = args.get('dir', 1)

    def _impl():
        if start is None:
            s = ida_ida.inf_get_min_ea()
        else:
            s = start
        flag = ida_bytes.BIN_SEARCH_FORWARD if direction else ida_bytes.BIN_SEARCH_BACKWARD
        flag |= ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW
        compiled = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(compiled, s, pat, 16)
        results = []
        ea = s
        for _ in range(256):
            ea = _bin_search_ea(ida_bytes.bin_search(ea, ida_ida.inf_get_max_ea(), compiled, flag))
            if ea == idaapi.BADADDR:
                break
            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else ''
            results.append([_hex(ea), fname])
            ea += 1
        return results
    return read(_impl)


def _strs(args):
    q = args.get('q', '')
    off = args.get('off', 0)
    n = min(args.get('n', 100), 1000)
    cache = get_cache()
    data = cache.get_strings(q, off, n)
    return [[_hex(ea), s, st] for ea, s, st in data]


def _imm(args):
    val = _ea(args['val'])
    def _impl():
        min_ea = ida_ida.inf_get_min_ea()
        max_ea = ida_ida.inf_get_max_ea()
        flag = ida_bytes.BIN_SEARCH_FORWARD | ida_bytes.BIN_SEARCH_NOBREAK | ida_bytes.BIN_SEARCH_NOSHOW

        if val <= 0xFF:
            w = 1
        elif val <= 0xFFFF:
            w = 2
        elif val <= 0xFFFFFFFF:
            w = 4
        else:
            w = 8

        pat_bytes = val.to_bytes(w, byteorder='little')
        pat_hex = ' '.join(f'{b:02X}' for b in pat_bytes)
        compiled = ida_bytes.compiled_binpat_vec_t()
        ida_bytes.parse_binpat_str(compiled, min_ea, pat_hex, 16)

        results = []
        ea = min_ea
        for _ in range(512):
            ea = _bin_search_ea(ida_bytes.bin_search(ea, max_ea, compiled, flag))
            if ea == idaapi.BADADDR:
                break
            func = ida_funcs.get_func(ea)
            fname = ida_funcs.get_func_name(func.start_ea) if func else ''
            results.append([_hex(ea), fname])
            ea += 1
            if len(results) >= 256:
                break
        return results
    return read(_impl)


# --- 4.10 Imports/Exports ---

def _imp(args):
    cache = get_cache()
    data = cache.get_imports()
    return [[mod, name, _hex(ea), ordinal] for mod, name, ea, ordinal in data]


def _exp(args):
    cache = get_cache()
    data = cache.get_exports()
    return [[_hex(ea), name, ordinal] for ea, name, ordinal in data]


def _ent(args):
    def _impl():
        results = []
        qty = ida_entry.get_entry_qty()
        for i in range(qty):
            ordinal = ida_entry.get_entry_ordinal(i)
            ea = ida_entry.get_entry(ordinal)
            name = ida_entry.get_entry_name(ordinal) or ''
            results.append([_hex(ea), name])
        return results
    return read(_impl)


# --- 4.11 CFG ---

def _cfg(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func'}
        fc = ida_gdl.FlowChart(func)
        nodes = []
        edges = []
        for block in fc:
            nodes.append([_hex(block.start_ea), _hex(block.end_ea)])
            for succ_block in _block_succs(block):
                edges.append([_hex(block.start_ea), _hex(succ_block.start_ea)])
        return {'n': nodes, 'e': edges}
    return read(_impl)


def _preds(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            if block.start_ea <= ea < block.end_ea:
                return [_hex(pred.start_ea) for pred in _block_preds(block)]
        return []
    return read(_impl)


def _succs(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return []
        fc = ida_gdl.FlowChart(func)
        for block in fc:
            if block.start_ea <= ea < block.end_ea:
                return [_hex(succ.start_ea) for succ in _block_succs(block)]
        return []
    return read(_impl)


# --- 4.17 Call trees ---

def _ctree(args):
    """Build forward call tree: function -> all callees recursively.
    Uses CodeRefsFrom which only returns code-to-code refs (faster than XrefsFrom)."""
    ea = _ea(args['a'])
    max_depth = min(args.get('depth', 5), 16)

    def _impl():
        tree = {}
        visited = set()

        def _walk(func_ea, depth):
            if depth > max_depth or func_ea in visited:
                return
            visited.add(func_ea)
            func = ida_funcs.get_func(func_ea)
            if not func:
                return
            seen = set()
            callees = []
            for item_ea in idautils.FuncItems(func.start_ea):
                for target in idautils.CodeRefsFrom(item_ea, 0):
                    tfunc = ida_funcs.get_func(target)
                    if tfunc and tfunc.start_ea != func_ea and tfunc.start_ea not in seen:
                        seen.add(tfunc.start_ea)
                        callees.append((tfunc.start_ea, ida_funcs.get_func_name(tfunc.start_ea) or ''))
            node_key = _hex(func_ea)
            tree[node_key] = {
                'name': ida_funcs.get_func_name(func_ea) or '',
                'calls': [[_hex(c[0]), c[1]] for c in callees]
            }
            for c_ea, _ in callees:
                _walk(c_ea, depth + 1)

        _walk(ea, 0)
        return tree
    return read(_impl)


def _ctreet(args):
    """Build reverse call tree: who calls this function, recursively up.
    Uses CodeRefsTo which is O(xrefs to entry point) per function, no FuncItems scan."""
    ea = _ea(args['a'])
    max_depth = min(args.get('depth', 5), 16)

    def _impl():
        tree = {}
        visited = set()

        def _walk(func_ea, depth):
            if depth > max_depth or func_ea in visited:
                return
            visited.add(func_ea)
            seen = set()
            callers = []
            for xref_ea in idautils.CodeRefsTo(func_ea, 0):
                cfunc = ida_funcs.get_func(xref_ea)
                if cfunc and cfunc.start_ea != func_ea and cfunc.start_ea not in seen:
                    seen.add(cfunc.start_ea)
                    callers.append((cfunc.start_ea, ida_funcs.get_func_name(cfunc.start_ea) or ''))
            node_key = _hex(func_ea)
            tree[node_key] = {
                'name': ida_funcs.get_func_name(func_ea) or '',
                'callers': [[_hex(c[0]), c[1]] for c in callers]
            }
            for c_ea, _ in callers:
                _walk(c_ea, depth + 1)

        _walk(ea, 0)
        return tree
    return read(_impl)


# --- 4.12 Patches & Bookmarks ---

def _pat(args):
    ea = _ea(args['a'])
    hexstr = args['hex']
    data = bytes.fromhex(hexstr)
    def _impl():
        for i, b in enumerate(data):
            ida_bytes.patch_byte(ea + i, b)
        return 'ok'
    return write(_impl)


def _patl(args):
    def _impl():
        patches = []
        class _visitor:
            def __call__(self, ea, fpos, o, v):
                patches.append([_hex(ea), format(o & 0xFF, '02x'), format(v & 0xFF, '02x')])
                return 0
        ida_bytes.visit_patched_bytes(0, idaapi.BADADDR, _visitor())
        return patches
    return read(_impl)


def _bml(args):
    def _impl():
        results = []
        slot = 1
        while True:
            ea = idc.get_bookmark(slot)
            if ea is None or ea == idaapi.BADADDR:
                break
            desc = idc.get_bookmark_desc(slot) or ''
            results.append([_hex(ea), desc])
            slot += 1
        return results
    return read(_impl)


def _bms(args):
    ea = _ea(args['a'])
    desc = args.get('desc', '')
    def _impl():
        slot = 1
        while True:
            existing = idc.get_bookmark(slot)
            if existing is None or existing == idaapi.BADADDR:
                break
            slot += 1
        idc.put_bookmark(ea, 0, 0, 0, slot, desc)
        return 'ok'
    return write(_impl)


def _bmd(args):
    ea = _ea(args['a'])
    def _impl():
        slot = 1
        while True:
            existing = idc.get_bookmark(slot)
            if existing is None or existing == idaapi.BADADDR:
                break
            if existing == ea:
                idc.put_bookmark(idaapi.BADADDR, 0, 0, 0, slot, '')
                return 'ok'
            slot += 1
        return 'not found'
    return write(_impl)


# --- 4.13 Analysis ---

def _aa(args):
    def _impl():
        ida_auto.auto_wait()
        return 'ok'
    return write(_impl)


def _mkfn(args):
    ea = _ea(args['a'])
    end = _ea(args['end']) if 'end' in args else idaapi.BADADDR
    def _impl():
        return 'ok' if ida_funcs.add_func(ea, end) else 'fail'
    return write(_impl)


def _delfn(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if func:
            ida_funcs.del_func(func.start_ea)
            return 'ok'
        return 'no func'
    return write(_impl)


def _mkdt(args):
    ea = _ea(args['a'])
    sz = args.get('sz', 1)
    dtype = args.get('type', 'byte')
    def _impl():
        type_map = {'byte': 1, 'word': 2, 'dword': 4, 'qword': 8}
        dsz = type_map.get(dtype, sz)
        if dsz == 1:
            ida_bytes.create_byte(ea, sz)
        elif dsz == 2:
            ida_bytes.create_word(ea, sz)
        elif dsz == 4:
            ida_bytes.create_dword(ea, sz)
        elif dsz == 8:
            ida_bytes.create_qword(ea, sz)
        return 'ok'
    return write(_impl)


def _undef(args):
    ea = _ea(args['a'])
    sz = args['sz']
    def _impl():
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, sz)
        return 'ok'
    return write(_impl)


# --- 4.14 Decompiler advanced ---

def _rnv(args):
    ea = _ea(args['a'])
    old = args['old']
    new = args['new']
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return 'decompile failed'
            lv = None
            for v in cfunc.lvars:
                if v.name == old:
                    lv = v
                    break
            if not lv:
                return 'var not found'
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.name = new
            if ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_NAME, lsi):
                return 'ok'
            return 'fail'
        except Exception as ex:
            return str(ex)
    return write(_impl)


def _rtv(args):
    ea = _ea(args['a'])
    var_name = args['var']
    decl = args['decl']
    def _impl():
        try:
            import ida_hexrays
            cfunc = ida_hexrays.decompile(ea)
            if not cfunc:
                return 'decompile failed'
            lv = None
            for v in cfunc.lvars:
                if v.name == var_name:
                    lv = v
                    break
            if not lv:
                return 'var not found'
            tif = ida_typeinf.tinfo_t()
            til = ida_typeinf.get_idati()
            decl_s = decl if decl.rstrip().endswith(';') else decl + ';'
            if not _parse_tinfo_decl(tif, til, decl_s):
                return 'parse error'
            lsi = ida_hexrays.lvar_saved_info_t()
            lsi.ll = lv
            lsi.type = tif
            if ida_hexrays.modify_user_lvar_info(cfunc.entry_ea, ida_hexrays.MLI_TYPE, lsi):
                return 'ok'
            return 'fail'
        except Exception as ex:
            return str(ex)
    return write(_impl)


# --- 4.18 Batch write tools ---

def _batch_set_names(args):
    entries = args['names']
    def _impl():
        ok = 0
        for item in entries:
            ea = _ea(item[0])
            name = item[1]
            if ida_name.set_name(ea, name, ida_name.SN_NOWARN):
                ok += 1
        return {'ok': ok, 'fail': len(entries) - ok}
    return write(_impl)


def _batch_set_comments(args):
    entries = args['comments']
    def _impl():
        for item in entries:
            ea = _ea(item[0])
            text = item[1]
            rep = bool(item[2]) if len(item) > 2 else False
            ida_bytes.set_cmt(ea, text, rep)
        return {'ok': len(entries)}
    return write(_impl)


def _batch_set_types(args):
    entries = args['types']
    def _impl():
        ok = 0
        for item in entries:
            ea = _ea(item[0])
            decl = item[1]
            if _apply_type_decl(ea, decl):
                ok += 1
        return {'ok': ok, 'fail': len(entries) - ok}
    return write(_impl)


# --- 4.19 Enhanced read tools ---

def _batch_decompile(args):
    addrs = [_ea(a) for a in args['addrs']]
    def _impl():
        try:
            import ida_hexrays
        except:
            return {'e': 'hexrays not available'}
        results = []
        for ea in addrs:
            try:
                cfunc = ida_hexrays.decompile(ea)
                if cfunc:
                    lines = cfunc.get_pseudocode()
                    text = '\n'.join(ida_lines.tag_remove(l.line) for l in lines)
                    results.append([_hex(ea), text])
                else:
                    results.append([_hex(ea), None])
            except:
                results.append([_hex(ea), None])
        return results
    return read(_impl)


def _get_func_by_addr(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no func at this addr'}
        start = func.start_ea
        name = ida_funcs.get_func_name(start) or ''
        cmt = ida_bytes.get_cmt(start, 0) or ida_bytes.get_cmt(start, 1) or ''
        return [_hex(start), name, cmt]
    return read(_impl)


# --- Kernel driver tools (iida-mcp-ioctl) ---

def _kernel_read(args):
    from .kdriver import read_kernel_memory
    return read_kernel_memory(_ea(args['a']), int(args['sz']))

def _kernel_modules(args):
    from .kdriver import get_module_list
    return get_module_list()

def _kernel_module_base(args):
    from .kdriver import get_module_base
    return get_module_base(args['name'])


def _kernel_read_values(args):
    from .kdriver import read_kernel_memory
    fmt = args.get('fmt', 'p').strip() or 'p'

    total = 0
    ops = []
    i = 0
    while i < len(fmt):
        c = fmt[i]
        if c == 'p':
            ops.append(('p', 8)); total += 8; i += 1
        elif c == 'd':
            ops.append(('d', 4)); total += 4; i += 1
        elif c == 'w':
            ops.append(('w', 2)); total += 2; i += 1
        elif c == 'b':
            ops.append(('b', 1)); total += 1; i += 1
        elif c == 's':
            ops.append(('s', 256)); total += 256; i += 1
        elif c.isdigit():
            j = i
            while j < len(fmt) and fmt[j].isdigit():
                j += 1
            if j < len(fmt) and fmt[j] == 'x':
                n = int(fmt[i:j])
                ops.append(('x', n)); total += n; i = j + 1
            else:
                return {'e': f'bad fmt at pos {i}: digits must end with x'}
        else:
            return {'e': f'bad fmt char: {c}'}

    if total == 0:
        return {'e': 'empty format'}
    if total > 65536:
        return {'e': 'total read too large'}

    def _read_one(addr_s):
        addr = _ea(addr_s)
        raw = read_kernel_memory(addr, total)
        if isinstance(raw, dict):
            return raw
        data = bytes.fromhex(raw)

        result = []
        off = 0
        for typ, sz in ops:
            if off + sz > len(data):
                result.append(None)
                break
            if typ == 'p':
                v = pystruct.unpack_from('<Q', data, off)[0]
                result.append(format(v, 'x'))
            elif typ == 'd':
                v = pystruct.unpack_from('<I', data, off)[0]
                result.append(v)
            elif typ == 'w':
                v = pystruct.unpack_from('<H', data, off)[0]
                result.append(v)
            elif typ == 'b':
                result.append(data[off])
            elif typ == 's':
                end = data.find(b'\x00', off, off + sz)
                if end == -1:
                    end = off + sz
                result.append(data[off:end].decode('utf-8', errors='replace'))
            elif typ == 'x':
                result.append(data[off:off + sz].hex())
            off += sz
        return result[0] if len(result) == 1 else result

    if 'addrs' in args:
        return [[a, _read_one(a)] for a in args.get('addrs', [])]
    if 'a' not in args:
        return {'e': 'a or addrs required'}
    return _read_one(args['a'])


def _ida_to_runtime(args):
    ea = _ea(args['a'])

    def _get_seg_and_pe():
        seg = ida_segment.getseg(ea)
        if not seg:
            return None
        seg_start = seg.start_ea
        seg_name = ida_segment.get_segm_name(seg)

        path = ida_nalt.get_input_file_path()
        image_base = 0
        sections = []
        try:
            with open(path, 'rb') as fp:
                dos = fp.read(64)
                if dos[:2] == b'MZ':
                    pe_off = pystruct.unpack_from('<I', dos, 60)[0]
                    fp.seek(pe_off + 4)
                    coff = fp.read(20)
                    nsections = pystruct.unpack_from('<H', coff, 2)[0]
                    opt_size = pystruct.unpack_from('<H', coff, 16)[0]
                    opt = fp.read(opt_size)
                    magic = pystruct.unpack_from('<H', opt, 0)[0]
                    if magic == 0x20b:
                        image_base = pystruct.unpack_from('<Q', opt, 24)[0]
                    else:
                        image_base = pystruct.unpack_from('<I', opt, 28)[0]
                    for _ in range(nsections):
                        shdr = fp.read(40)
                        sname = shdr[:8].rstrip(b'\x00').decode('ascii', errors='replace')
                        vaddr = pystruct.unpack_from('<I', shdr, 12)[0]
                        sections.append((sname, vaddr))
        except:
            pass

        return {
            'ea': ea,
            'seg_start': seg_start,
            'seg_name': seg_name,
            'image_base': image_base,
            'sections': sections,
            'filename': os.path.basename(path)
        }

    info = read(_get_seg_and_pe)
    if info is None:
        return {'e': f'address {_hex(ea)} not in any segment'}

    rva = ea - info['image_base']

    mod_name = args.get('mod', '')
    if not mod_name:
        fname = info['filename']
        dot = fname.rfind('.')
        mod_name = fname[:dot] if dot > 0 else fname

    from .kdriver import get_module_base
    mod_result = get_module_base(mod_name)
    if isinstance(mod_result, dict) and 'e' in mod_result:
        return {'e': f'driver: {mod_result["e"]}. provide mod= or load driver.', 'rva': _hex(rva)}

    runtime_base = int(mod_result[0], 16)
    runtime_addr = runtime_base + rva

    return {
        'ida': _hex(ea),
        'rva': _hex(rva),
        'runtime_base': mod_result[0],
        'runtime': format(runtime_addr, 'x'),
        'mod': mod_name
    }


# --- Standalone utilities (no IDB required) ---

_CALC_ALLOWED = set('0123456789abcdefABCDEFxXoObB+-*/%()<>&|^~ \t')

def _calc(args):
    expr = args['expr'].strip()
    if not expr:
        return {'e': 'empty expression'}
    if not all(c in _CALC_ALLOWED for c in expr):
        return {'e': 'invalid characters in expression'}
    try:
        val = eval(compile(expr, '<calc>', 'eval', flags=0), {"__builtins__": {}}, {})
        if not isinstance(val, int):
            return {'e': 'result is not integer'}
        return [val, format(val & 0xFFFFFFFFFFFFFFFF, 'x')]
    except Exception as ex:
        return {'e': str(ex)}


def _disasm_bytes(args):
    try:
        import capstone
    except ImportError:
        return {'e': 'capstone not installed (pip install capstone)'}

    raw = bytes.fromhex(args['hex'].replace(' ', ''))
    arch_str = args.get('arch', 'x64').lower()
    base = _ea(args['addr']) if 'addr' in args else 0

    arch_map = {
        'x86':   (capstone.CS_ARCH_X86, capstone.CS_MODE_32),
        'x64':   (capstone.CS_ARCH_X86, capstone.CS_MODE_64),
        'arm':   (capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM),
        'arm64': (capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM),
    }
    if arch_str not in arch_map:
        return {'e': f'unknown arch: {arch_str}, use x86/x64/arm/arm64'}

    cs_arch, cs_mode = arch_map[arch_str]
    md = capstone.Cs(cs_arch, cs_mode)
    result = []
    for insn in md.disasm(raw, base):
        result.append([format(insn.address, 'x'), insn.bytes.hex(), insn.mnemonic, insn.op_str])
    if not result:
        return {'e': 'no valid instructions'}
    return result


# ============================================================
# Dispatch table
# ============================================================

# ============================================================
# Compatibility tools (mrexodia/ida-pro-mcp parity)
# ============================================================

# --- UI cursor ---

def _chkconn(args):
    return 'ok'


def _gca(args):
    def _impl():
        return _hex(idaapi.get_screen_ea())
    return read(_impl)


def _gcf(args):
    def _impl():
        ea = idaapi.get_screen_ea()
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function at cursor'}
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size(),
        ]
    return read(_impl)


def _gfbn(args):
    name = args['name']
    def _impl():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {'e': 'not found'}
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'name exists but not a function', 'addr': _hex(ea)}
        return [
            _hex(func.start_ea),
            ida_funcs.get_func_name(func.start_ea),
            func.size(),
        ]
    return read(_impl)


# --- Typed data reads ---

def _drb(args):
    ea = _ea(args['a'])
    def _impl():
        v = idc.get_wide_byte(ea)
        return [v, _hex(v)]
    return read(_impl)


def _drw(args):
    ea = _ea(args['a'])
    def _impl():
        v = idc.get_wide_word(ea)
        return [v, _hex(v)]
    return read(_impl)


def _drd(args):
    ea = _ea(args['a'])
    def _impl():
        v = idc.get_wide_dword(ea)
        return [v, _hex(v)]
    return read(_impl)


def _drq(args):
    ea = _ea(args['a'])
    def _impl():
        v = idc.get_qword(ea)
        return [v, _hex(v)]
    return read(_impl)


def _drs(args):
    ea = _ea(args['a'])
    strtype = args.get('strtype', -1)
    maxlen = min(args.get('max', 4096), 0x100000)
    def _impl():
        try:
            st = strtype if strtype >= 0 else ida_nalt.get_default_str_type()
            data = idc.get_strlit_contents(ea, maxlen, st)
            if data is None:
                # Fallback: read C string manually
                raw = ida_bytes.get_bytes(ea, maxlen) or b''
                nul = raw.find(b'\x00')
                if nul >= 0:
                    raw = raw[:nul]
                return raw.decode('utf-8', errors='replace')
            return data.decode('utf-8', errors='replace') if isinstance(data, (bytes, bytearray)) else str(data)
        except Exception as ex:
            return {'e': str(ex)}
    return read(_impl)


# --- Type declaration ---

def _dct(args):
    decl = args['decl']
    def _impl():
        til = ida_typeinf.get_idati()
        flags = getattr(ida_typeinf, 'HTI_DCL', 0) | getattr(ida_typeinf, 'HTI_PAK1', 0)
        try:
            errs = ida_typeinf.parse_decls(til, decl, None, flags)
            return {'errors': errs}
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _sfp(args):
    ea = _ea(args['a'])
    proto = args['decl']
    def _impl():
        return 'ok' if _apply_type_decl(ea, proto) else 'fail'
    return write(_impl)


# --- Global variable values ---

def _gvva(args):
    ea = _ea(args['a'])
    sz = args.get('sz', 0)
    def _impl():
        name = ida_name.get_name(ea) or ''
        if sz:
            data = ida_bytes.get_bytes(ea, min(sz, 0x100000)) or b''
            return {'addr': _hex(ea), 'name': name, 'raw': data.hex()}
        # Auto-detect size from item
        isz = ida_bytes.get_item_size(ea) or 0
        if isz <= 0 or isz > 16:
            isz = 8 if ida_ida.inf_is_64bit() else 4
        if isz == 1:
            v = idc.get_wide_byte(ea)
        elif isz == 2:
            v = idc.get_wide_word(ea)
        elif isz == 4:
            v = idc.get_wide_dword(ea)
        elif isz == 8:
            v = idc.get_qword(ea)
        else:
            data = ida_bytes.get_bytes(ea, isz) or b''
            return {'addr': _hex(ea), 'name': name, 'size': isz, 'raw': data.hex()}
        return {'addr': _hex(ea), 'name': name, 'size': isz, 'value': _hex(v), 'dec': v}
    return read(_impl)


def _gvvn(args):
    name = args['name']
    def _impl():
        ea = ida_name.get_name_ea(idaapi.BADADDR, name)
        if ea == idaapi.BADADDR:
            return {'e': 'name not found'}
        return ea
    ea = read(_impl)
    if isinstance(ea, dict):
        return ea
    return _gvva({'a': _hex(ea), 'sz': args.get('sz', 0)})


# --- patch_assemble (keystone) ---

_KS_CACHE = {}

def _ks_for_arch(procname, bits):
    """Build a keystone (arch, mode) tuple for the current IDA target."""
    try:
        import keystone
    except ImportError:
        return None
    pn = (procname or '').lower()
    key = (pn, bits)
    if key in _KS_CACHE:
        return _KS_CACHE[key]
    arch, mode = None, None
    if pn.startswith('metapc') or pn.startswith('80'):
        arch = keystone.KS_ARCH_X86
        mode = keystone.KS_MODE_64 if bits == 64 else (keystone.KS_MODE_32 if bits == 32 else keystone.KS_MODE_16)
    elif pn.startswith('arm'):
        if bits == 64:
            arch, mode = keystone.KS_ARCH_ARM64, keystone.KS_MODE_LITTLE_ENDIAN
        else:
            arch, mode = keystone.KS_ARCH_ARM, keystone.KS_MODE_ARM
    elif pn.startswith('mips'):
        arch = keystone.KS_ARCH_MIPS
        mode = (keystone.KS_MODE_MIPS64 if bits == 64 else keystone.KS_MODE_MIPS32) | keystone.KS_MODE_LITTLE_ENDIAN
    elif pn.startswith('ppc'):
        arch = keystone.KS_ARCH_PPC
        mode = (keystone.KS_MODE_PPC64 if bits == 64 else keystone.KS_MODE_PPC32) | keystone.KS_MODE_BIG_ENDIAN
    if arch is None:
        _KS_CACHE[key] = None
        return None
    ks = keystone.Ks(arch, mode)
    _KS_CACHE[key] = ks
    return ks


def _pasm(args):
    ea = _ea(args['a'])
    asm = args['asm']
    def _impl():
        procname = ida_ida.inf_get_procname()
        bits = 64 if ida_ida.inf_is_64bit() else (32 if (ida_ida.inf_is_32bit_exactly() if hasattr(ida_ida, 'inf_is_32bit_exactly') else True) else 16)
        ks = _ks_for_arch(procname, bits)
        if ks is None:
            return {'e': f'no keystone backend for proc={procname} bits={bits}'}
        try:
            encoding, count = ks.asm(asm.encode('utf-8'), ea)
        except Exception as ex:
            return {'e': f'assemble failed: {ex}'}
        if not encoding:
            return {'e': 'assemble produced no bytes'}
        data = bytes(encoding)
        for i, b in enumerate(data):
            ida_bytes.patch_byte(ea + i, b)
        return {'addr': _hex(ea), 'bytes': data.hex(), 'count': count}
    return write(_impl)


# --- Globals listing ---

def _lg(args):
    q = (args.get('q') or '').lower()
    n = min(args.get('n', 200), 5000)
    def _impl():
        results = []
        for ea, name in idautils.Names():
            if ida_funcs.get_func(ea) is not None:
                # Skip function entry names
                if ida_funcs.get_func(ea).start_ea == ea:
                    continue
            if q and q not in name.lower():
                continue
            sz = ida_bytes.get_item_size(ea) or 0
            tif = ida_typeinf.tinfo_t()
            tstr = str(tif) if idaapi.get_tinfo(tif, ea) and tif.present() else ''
            row = [_hex(ea), name, sz]
            if tstr:
                row.append(tstr)
            results.append(row)
            if len(results) >= n:
                break
        return results
    return read(_impl)


def _gsa(args):
    ea = _ea(args['a'])
    def _impl():
        tif = ida_typeinf.tinfo_t()
        if not idaapi.get_tinfo(tif, ea):
            return {'e': 'no type at address'}
        if not tif.is_struct():
            return {'e': 'not a struct', 'type': str(tif)}
        name = tif.get_type_name() or ''
        return {'addr': _hex(ea), 'name': name, 'size': tif.get_size(), 'decl': tif.dstr()}
    return read(_impl)


def _xtof(args):
    """Cross-references to a struct field. Returns addresses that use struct.field."""
    sname = args['struct']
    fname = args['field']
    def _impl():
        til = ida_typeinf.get_idati()
        tif = ida_typeinf.tinfo_t()
        if not tif.get_named_type(til, sname):
            return {'e': 'struct not found'}
        # Find member offset
        try:
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return {'e': 'cannot read struct members'}
            target_off = None
            for m in udt:
                mname = _struct_member_attr(m, 'name', '') or ''
                if mname == fname:
                    target_off = (_struct_member_attr(m, 'offset', 0) or 0) // 8
                    break
            if target_off is None:
                return {'e': 'field not found'}
        except Exception as ex:
            return {'e': f'member lookup failed: {ex}'}
        # Use the struct's tid + member offset to find xrefs
        try:
            tid = tif.get_tid() if hasattr(tif, 'get_tid') else idaapi.BADADDR
        except:
            tid = idaapi.BADADDR
        results = []
        if tid != idaapi.BADADDR:
            try:
                member_id = ida_typeinf.get_udm_tid(tif, target_off * 8) if hasattr(ida_typeinf, 'get_udm_tid') else idaapi.BADADDR
            except:
                member_id = idaapi.BADADDR
            if member_id != idaapi.BADADDR:
                for xref in idautils.XrefsTo(member_id):
                    fn = ida_funcs.get_func(xref.frm)
                    fname2 = ida_funcs.get_func_name(fn.start_ea) if fn else ''
                    results.append([_hex(xref.frm), fname2, xref.type])
        return {'struct': sname, 'field': fname, 'offset': target_off, 'xrefs': results}
    return read(_impl)


# --- Stack frame variable CRUD ---

def _func_frame_tif(func):
    """Get the function's frame as a tinfo_t (IDA 9.x style) or fallback to struct ID."""
    if hasattr(ida_frame, 'get_func_frame'):
        try:
            tif = ida_typeinf.tinfo_t()
            if ida_frame.get_func_frame(tif, func):
                return tif
        except:
            pass
    return None


def _sfvl(args):
    ea = _ea(args['a'])
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function'}
        tif = _func_frame_tif(func)
        if tif is not None:
            udt = ida_typeinf.udt_type_data_t()
            if not tif.get_udt_details(udt):
                return []
            out = []
            for m in udt:
                mname = _struct_member_attr(m, 'name', '') or ''
                off_bits = _struct_member_attr(m, 'offset', 0) or 0
                size_bits = _struct_member_bits(m)
                mt = _struct_member_attr(m, 'type')
                out.append([
                    off_bits // 8,
                    size_bits // 8 if size_bits else 0,
                    mname,
                    str(mt) if mt else '',
                ])
            return out
        # Legacy frame struct fallback
        frame_id = func.frame
        if frame_id == idaapi.BADADDR:
            return []
        try:
            import ida_struct
            sptr = ida_struct.get_struct(frame_id)
            if not sptr:
                return []
            out = []
            for i in range(sptr.memqty):
                m = sptr.get_member(i)
                if not m:
                    continue
                out.append([m.soff, m.eoff - m.soff, ida_struct.get_member_name(m.id) or '', ''])
            return out
        except Exception as ex:
            return {'e': str(ex)}
    return read(_impl)


def _sfvc(args):
    ea = _ea(args['a'])
    name = args['name']
    offset = args['offset'] if isinstance(args['offset'], int) else int(args['offset'], 0)
    decl = args.get('decl', '')
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function'}
        # Try modern udm API first
        tif = _func_frame_tif(func)
        if tif is not None and hasattr(ida_typeinf, 'udm_t'):
            udm = ida_typeinf.udm_t()
            udm.name = name
            udm.offset = offset * 8
            mtif = ida_typeinf.tinfo_t()
            if decl:
                if not _parse_tinfo_decl(mtif, ida_typeinf.get_idati(), decl if decl.rstrip().endswith(';') else decl + ';'):
                    return {'e': 'parse type failed'}
            else:
                # Default to _BYTE
                _parse_tinfo_decl(mtif, ida_typeinf.get_idati(), 'unsigned char;')
            udm.type = mtif
            udm.size = mtif.get_size() * 8 if mtif.get_size() > 0 else 8
            try:
                r = tif.add_udm(udm)
                if r >= 0 or r == 0:
                    return 'ok'
                return {'e': f'add_udm returned {r}'}
            except Exception as ex:
                return {'e': str(ex)}
        # Legacy fallback
        try:
            import ida_struct
            frame_id = func.frame
            sptr = ida_struct.get_struct(frame_id)
            if not sptr:
                return {'e': 'no frame'}
            sz = 1
            if decl:
                tif2 = ida_typeinf.tinfo_t()
                if _parse_tinfo_decl(tif2, ida_typeinf.get_idati(), decl if decl.rstrip().endswith(';') else decl + ';'):
                    sz = max(tif2.get_size(), 1)
            r = ida_struct.add_struc_member(sptr, name, offset, ida_bytes.byte_flag() if sz == 1 else ida_bytes.dword_flag(), None, sz)
            return 'ok' if r == 0 else {'e': f'add_struc_member rc={r}'}
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _sfvd(args):
    ea = _ea(args['a'])
    name = args['name']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function'}
        tif = _func_frame_tif(func)
        if tif is not None:
            try:
                udm_idx = tif.find_udm(name) if hasattr(tif, 'find_udm') else -1
            except:
                udm_idx = -1
            if udm_idx is not None and udm_idx >= 0:
                try:
                    if tif.del_udm(udm_idx) == 0:
                        return 'ok'
                except Exception as ex:
                    return {'e': str(ex)}
            return {'e': 'member not found'}
        # Legacy
        try:
            import ida_struct
            sptr = ida_struct.get_struct(func.frame)
            if not sptr:
                return {'e': 'no frame'}
            m = ida_struct.get_member_by_name(sptr, name)
            if not m:
                return {'e': 'not found'}
            ida_struct.del_struc_member(sptr, m.soff)
            return 'ok'
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _sfvr(args):
    ea = _ea(args['a'])
    old = args['old']
    new = args['new']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function'}
        tif = _func_frame_tif(func)
        if tif is not None:
            try:
                idx = tif.find_udm(old) if hasattr(tif, 'find_udm') else -1
            except:
                idx = -1
            if idx is None or idx < 0:
                return {'e': 'var not found'}
            try:
                if tif.rename_udm(idx, new) == 0:
                    return 'ok'
                return {'e': 'rename_udm failed'}
            except Exception as ex:
                return {'e': str(ex)}
        # Legacy
        try:
            import ida_struct
            sptr = ida_struct.get_struct(func.frame)
            m = ida_struct.get_member_by_name(sptr, old)
            if not m:
                return {'e': 'not found'}
            return 'ok' if ida_struct.set_member_name(sptr, m.soff, new) else {'e': 'fail'}
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


def _sfvt(args):
    ea = _ea(args['a'])
    name = args['name']
    decl = args['decl']
    def _impl():
        func = ida_funcs.get_func(ea)
        if not func:
            return {'e': 'no function'}
        til = ida_typeinf.get_idati()
        mtif = ida_typeinf.tinfo_t()
        if not _parse_tinfo_decl(mtif, til, decl if decl.rstrip().endswith(';') else decl + ';'):
            return {'e': 'parse type failed'}
        tif = _func_frame_tif(func)
        if tif is not None:
            try:
                idx = tif.find_udm(name) if hasattr(tif, 'find_udm') else -1
            except:
                idx = -1
            if idx is None or idx < 0:
                return {'e': 'var not found'}
            try:
                if tif.set_udm_type(idx, mtif) == 0:
                    return 'ok'
                return {'e': 'set_udm_type failed'}
            except Exception as ex:
                return {'e': str(ex)}
        # Legacy
        try:
            import ida_struct
            sptr = ida_struct.get_struct(func.frame)
            m = ida_struct.get_member_by_name(sptr, name)
            if not m:
                return {'e': 'not found'}
            r = ida_struct.set_member_tinfo(sptr, m, 0, mtif, 0)
            return 'ok' if r else {'e': 'set_member_tinfo failed'}
        except Exception as ex:
            return {'e': str(ex)}
    return write(_impl)


DISPATCH = {
    'get_info': _info,
    'read_file_bytes': _fraw,
    'addr_to_fileoff': _fmap,
    'get_filepath': _fpath,
    'parse_pe': _pe,
    'parse_elf': _elf,
    'list_functions': _fl,
    'get_func_info': _fi,
    'decompile': _dec,
    'get_func_type': _decl,
    'get_callers': _cf,
    'get_callees': _ct,
    'get_local_vars': _fv,
    'get_func_args': _fa,
    'disassemble': _dis,
    'read_bytes': _rb,
    'write_bytes': _wb,
    'get_head': _head,
    'get_name': _gn,
    'set_name': _sn,
    'get_comment': _gc,
    'set_comment': _sc,
    'search_names': _an,
    'get_type': _gt,
    'set_type': _st,
    'list_structs': _tl,
    'get_struct': _tg,
    'get_struct_details': _tgd,
    'read_struct': _read_struct,
    'set_struct': _ts,
    'delete_struct': _td,
    'list_enums': _el,
    'get_enum': _eg,
    'find_enum_value': _find_enum_value,
    'set_enum': _es,
    'list_local_types': _lti,
    'get_local_type': _ltg,
    'set_local_type': _lts,
    'list_segments': _segs,
    'get_segment_info': _segi,
    'xrefs_to': _xto,
    'xrefs_from': _xfrom,
    'search_bytes': _srch,
    'search_strings': _strs,
    'search_imm': _imm,
    'list_imports': _imp,
    'list_exports': _exp,
    'list_entries': _ent,
    'get_cfg': _cfg,
    'get_predecessors': _preds,
    'get_successors': _succs,
    'patch_bytes': _pat,
    'patch_list': _patl,
    'bookmark_list': _bml,
    'bookmark_set': _bms,
    'bookmark_delete': _bmd,
    'reanalyze': _aa,
    'create_function': _mkfn,
    'delete_function': _delfn,
    'make_data': _mkdt,
    'undefine': _undef,
    'rename_var': _rnv,
    'retype_var': _rtv,
    'call_tree': _ctree,
    'callers_tree': _ctreet,
    'batch_set_names': _batch_set_names,
    'batch_set_comments': _batch_set_comments,
    'batch_set_types': _batch_set_types,
    'batch_decompile': _batch_decompile,
    'get_func_by_addr': _get_func_by_addr,
    'kernel_read': _kernel_read,
    'kernel_modules': _kernel_modules,
    'kernel_module_base': _kernel_module_base,
    'kernel_read_values': _kernel_read_values,
    'ida_to_runtime': _ida_to_runtime,
    'calc': _calc,
    'disasm_bytes': _disasm_bytes,

    # --- mrexodia parity: aliases ---
    'check_connection': _chkconn,
    'get_metadata': _info,
    'get_current_address': _gca,
    'get_current_function': _gcf,
    'get_function_by_name': _gfbn,
    'get_function_by_address': _fi,
    'convert_number': _calc,
    'list_functions_filter': _fl,
    'list_strings': _strs,
    'list_strings_filter': _strs,
    'decompile_function': _dec,
    'disassemble_function': _dis,
    'get_xrefs_to': _xto,
    'get_xrefs_to_field': _xtof,
    'get_entry_points': _ent,
    'rename_local_variable': _rnv,
    'rename_global_variable': _sn,
    'set_global_variable_type': _st,
    'rename_function': _sn,
    'set_local_variable_type': _rtv,
    'get_defined_structures': _tl,
    'analyze_struct_detailed': _tgd,
    'get_struct_at_address': _gsa,
    'get_struct_info_simple': _tg,
    'search_structures': _tl,
    'read_memory_bytes': _rb,

    # --- mrexodia parity: new implementations ---
    'data_read_byte': _drb,
    'data_read_word': _drw,
    'data_read_dword': _drd,
    'data_read_qword': _drq,
    'data_read_string': _drs,
    'declare_c_type': _dct,
    'set_function_prototype': _sfp,
    'patch_address_assembles': _pasm,
    'get_global_variable_value_by_name': _gvvn,
    'get_global_variable_value_at_address': _gvva,
    'list_globals': _lg,
    'list_globals_filter': _lg,
    'get_stack_frame_variables': _sfvl,
    'create_stack_frame_variable': _sfvc,
    'delete_stack_frame_variable': _sfvd,
    'rename_stack_frame_variable': _sfvr,
    'set_stack_frame_variable_type': _sfvt,
}


_CACHE_INVALIDATING = frozenset([
    'set_name', 'write_bytes', 'set_type', 'set_struct', 'delete_struct',
    'set_enum', 'set_local_type', 'patch_bytes',
    'create_function', 'delete_function', 'make_data', 'undefine', 'reanalyze',
    'batch_set_names', 'batch_set_comments', 'batch_set_types',
    # mrexodia parity
    'rename_global_variable', 'set_global_variable_type', 'rename_function',
    'declare_c_type', 'set_function_prototype', 'patch_address_assembles',
    'create_stack_frame_variable', 'delete_stack_frame_variable',
    'rename_stack_frame_variable', 'set_stack_frame_variable_type',
])


def execute_tool(tool, args):
    """Execute a single tool. Used as local_handler."""
    fn = DISPATCH.get(tool)
    if not fn:
        return {'e': f'unknown tool: {tool}'}
    try:
        result = fn(args)
        if tool in _CACHE_INVALIDATING:
            import threading
            cache = get_cache()
            cache.invalidate()
            threading.Thread(target=cache.ensure_built, daemon=True).start()
        return result
    except Exception as ex:
        return {'e': str(ex)}

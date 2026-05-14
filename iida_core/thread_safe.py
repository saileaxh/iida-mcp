"""Thread-safe IDA API execution wrapper.
All IDA API calls run in batch mode to suppress modal dialogs/warnings."""
import threading

import ida_kernwin

MFF_READ = ida_kernwin.MFF_READ
MFF_WRITE = ida_kernwin.MFF_WRITE

_batch_fn = None  # lazy-init: callable(int) -> old_value, or False if unavailable


def _get_batch_fn():
    """Lazily detect the batch mode API."""
    global _batch_fn
    if _batch_fn is not None:
        return _batch_fn
    # idc.batch(v) returns the previous batch value -- works on IDA 7.x-9.x
    try:
        import idc
        old = idc.batch(0)
        idc.batch(old)
        _batch_fn = idc.batch
        return _batch_fn
    except:
        pass
    try:
        import idaapi
        if hasattr(idaapi, 'cvar') and hasattr(idaapi.cvar, 'batch'):
            def _set(v):
                old = idaapi.cvar.batch
                idaapi.cvar.batch = v
                return old
            _batch_fn = _set
            return _batch_fn
    except:
        pass
    _batch_fn = False
    return _batch_fn


# Max seconds to wait for IDA main thread to run the callback.
# If exceeded, the request fails fast instead of leaking the handler thread
# (otherwise the HTTP server stays in CLOSE_WAIT forever and exhausts backlog).
IDA_SYNC_TIMEOUT = 60.0


def run_in_ida(fn, *args, write=False):
    """Execute fn(*args) on IDA's main thread, blocking until done.
    Temporarily enables batch mode to suppress all dialogs."""
    result = [None]
    exc = [None]
    ev = threading.Event()

    def _run():
        batch = _get_batch_fn()
        prev = None
        try:
            if batch:
                prev = batch(1)
            result[0] = fn(*args)
        except Exception as e:
            exc[0] = e
        finally:
            if batch and prev is not None:
                batch(prev)
            ev.set()
        return 0

    mode = MFF_WRITE if write else MFF_READ
    ida_kernwin.execute_sync(_run, mode)
    if not ev.wait(IDA_SYNC_TIMEOUT):
        raise TimeoutError(
            f'IDA main thread did not run callback within {IDA_SYNC_TIMEOUT}s'
        )
    if exc[0]:
        raise exc[0]
    return result[0]


def read(fn, *args):
    """Shorthand for run_in_ida with MFF_READ."""
    return run_in_ida(fn, *args, write=False)


def write(fn, *args):
    """Shorthand for run_in_ida with MFF_WRITE."""
    return run_in_ida(fn, *args, write=True)

from __future__ import annotations

import threading
import time

from patatt import _run_command

# A child that exits immediately (code 2) but backgrounds a grandchild which
# keeps the inherited stdout/stderr file descriptors open. This is the exact
# shape of gpg spawning gpg-agent/scdaemon: gpg itself exits, but a lingering
# daemon holds the write end of the captured pipe. With capture_output pipes,
# subprocess.run's drain never sees EOF and blocks until the grandchild dies;
# with file redirection it returns as soon as the direct child exits.
LINGER_SECONDS = 10
LINGER_CMD = ['sh', '-c', f'sleep {LINGER_SECONDS} & exit 2']

# The direct child exits instantly, so a correct implementation returns well
# under a second. Anything past this deadline means we are stuck waiting on the
# lingering grandchild.
RETURN_DEADLINE = 5.0


def test_run_command_does_not_wait_for_lingering_child() -> None:
    """_run_command must return when the invoked command exits, even if a
    daemon-like grandchild keeps the inherited stdout/stderr FDs open.

    Runs the call in a daemon thread so a regression surfaces as a prompt
    assertion failure at RETURN_DEADLINE rather than hanging the test suite.
    """
    holder: list[tuple[int, bytes, bytes]] = []

    def target() -> None:
        holder.append(_run_command(LINGER_CMD))

    thread = threading.Thread(target=target, daemon=True)
    started = time.monotonic()
    thread.start()
    thread.join(timeout=RETURN_DEADLINE)
    elapsed = time.monotonic() - started

    assert not thread.is_alive(), (
        f'_run_command did not return within {RETURN_DEADLINE}s: a lingering '
        'child is holding the captured stdout/stderr pipe open '
        '(gpg-agent/scdaemon hang)'
    )
    assert elapsed < RETURN_DEADLINE

    ecode, _, _ = holder[0]
    assert ecode == 2

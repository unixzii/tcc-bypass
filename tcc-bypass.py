#!/usr/bin/env python3
"""Temporarily bypass TCC permission audit."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

HERE = Path(__file__).resolve().parent
LIBRARY = HERE / 'libtccd_inject.dylib'
HELPER = HERE / 'tccd_control_helper'
TCCD = '/System/Library/PrivateFrameworks/TCC.framework/Support/tccd'


def log(message, warning=False):
    for line in str(message).lower().splitlines():
        print(
            f'{"[!]" if warning else "[*]"} {line}',
            file=sys.stderr if warning else sys.stdout,
            flush=True,
        )


def build(force=False):
    subprocess.run(
        ['/usr/bin/make', *(['-B'] if force else []), 'all'],
        cwd=HERE,
        check=True,
    )


def root():
    if os.geteuid() != 0:
        os.execv(
            '/usr/bin/sudo',
            ['sudo', '--', sys.executable, str(Path(__file__).resolve()), *sys.argv[1:]],
        )


def targets():
    result = subprocess.run(['/usr/bin/pgrep', '-x', 'tccd'], text=True, capture_output=True)
    if result.returncode not in (0, 1):
        raise RuntimeError(result.stderr.strip() or 'pgrep failed')
    pids = list(map(int, result.stdout.split()))
    if not pids:
        raise RuntimeError('no running tccd')
    for pid in pids:
        path = subprocess.check_output(
            ['/bin/ps', '-p', str(pid), '-o', 'comm='], text=True
        ).strip()
        if os.path.realpath(path) != TCCD:
            raise RuntimeError(f'pid {pid} identity changed')
    return pids


def inject(pid):
    program = f'pid={pid}\nlibrary={str(LIBRARY)!r}\n' + r'''
import lldb, os, json

report = None
target = lldb.debugger.CreateTarget("")
error = lldb.SBError()
process = target.AttachToProcessWithID(lldb.debugger.GetListener(), pid, error)

if error.Fail():
    print("INJECT_ERROR " + str(error))
else:
    try:
        spec = target.GetExecutable()
        if (
            os.path.join(spec.GetDirectory() or "", spec.GetFilename() or "")
            != "/System/Library/PrivateFrameworks/TCC.framework/Support/tccd"
        ):
            raise RuntimeError("target is not tccd")

        loaded = False
        for index in range(target.GetNumModules()):
            name = target.GetModuleAtIndex(index).GetFileSpec().GetFilename() or ""
            loaded |= name == "libtccd_inject.dylib"
        if not loaded:
            process.LoadImage(lldb.SBFileSpec(library), error)
            if error.Fail():
                raise RuntimeError(str(error))

        def address(name):
            symbols = target.FindSymbols(name, lldb.eSymbolTypeData)
            if symbols.GetSize() != 1:
                raise RuntimeError("missing symbol " + name)
            return symbols.GetContextAtIndex(0).GetSymbol().GetStartAddress().GetLoadAddress(target)

        def integer(name):
            value = process.ReadUnsignedFromMemory(address(name), 4, error)
            if error.Fail():
                raise RuntimeError(str(error))
            return value

        ready = integer("cyan_tccd_inject_ready")
        receive = integer("cyan_tccd_control_receive")
        if ready != 1 or not receive:
            raise RuntimeError("injection did not initialize")
        report = {"pid": pid, "receive": receive}
    except Exception as failure:
        print("INJECT_ERROR " + str(failure))
    finally:
        detached = process.Detach()
        if detached.Fail():
            print("INJECT_ERROR detach: " + str(detached))
            report = None

    if report:
        print("INJECT_RESULT " + json.dumps(report))
'''
    log(f'injecting tccd pid {pid}')
    result = subprocess.run(
        [
            '/usr/bin/xcrun', 'lldb', '--batch', '--no-lldbinit',
            '-o', 'script exec(' + json.dumps(program) + ')', '-o', 'quit',
        ],
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )

    # LLDB detach can leave a job-control stop in this research environment.
    # Resume after the debugger has exited, including when image loading failed.
    state = subprocess.check_output(
        ['/bin/ps', '-p', str(pid), '-o', 'stat='], text=True
    ).strip()
    if 'T' in state:
        os.kill(pid, signal.SIGCONT)
    records = [
        line[len('INJECT_RESULT '):]
        for line in result.stdout.splitlines()
        if line.startswith('INJECT_RESULT ')
    ]
    if result.returncode or len(records) != 1:
        errors = [line for line in result.stdout.splitlines() if line.startswith('INJECT_ERROR ')]
        raise RuntimeError('\n'.join(errors) or result.stdout)
    return json.loads(records[0])


def bootstrap():
    # Reuse a healthy resident helper. Native status already performs a fresh
    # round trip to every tccd and detects new/unattached instances.
    current = subprocess.run([str(HELPER), 'status', '--json'], text=True, capture_output=True)
    if current.returncode == 0:
        value = json.loads(current.stdout)
        log(f'using helper pid {value["helper_pid"]}, connected {value["connected"]} tccd instances')
        return

    connections = [inject(pid) for pid in targets()]
    encoded = json.dumps(connections)
    result = subprocess.run([str(HELPER), '_attach', encoded], text=True, capture_output=True)
    child = None
    if result.returncode == 69:
        child = subprocess.Popen(
            [str(HELPER), '_serve', encoded],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise RuntimeError('helper failed to start; check lifecycle os_log')
            result = subprocess.run([str(HELPER), '_attach', encoded], text=True, capture_output=True)
            if result.returncode != 69:
                break
            time.sleep(.1)

    if result.returncode:
        raise RuntimeError(result.stdout or result.stderr or 'helper setup failed')
    reply = json.loads(result.stdout)
    log(f'helper pid {reply["helper_pid"]}, connected {reply["connected"]} tccd instances')


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(
            'usage: tcc-bypass.py build [--force] | start [minutes] | stop | status | logs [--snapshot]'
        )
        return 0

    command, arguments = sys.argv[1], sys.argv[2:]

    if command == 'build':
        if arguments not in ([], ['--force']):
            raise RuntimeError('usage: build [--force]')
        build(bool(arguments))
        return 0

    if command in ('start', 'enable'):
        root()
        bootstrap()
        os.execv(str(HELPER), [str(HELPER), 'enable', *arguments])

    forwarded = {'stop': 'disable', 'disable': 'disable', 'status': 'status', 'logs': 'logs'}
    if command not in forwarded:
        raise RuntimeError('unknown command')
    if not HELPER.is_file():
        raise RuntimeError('missing binaries; run build first')

    root()
    os.execv(str(HELPER), [str(HELPER), forwarded[command], *arguments])


if __name__ == '__main__':
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        sys.exit(130)
    except (OSError, RuntimeError, ValueError, subprocess.CalledProcessError) as error:
        log(error, warning=True)
        sys.exit(1)

# tcc-bypass

A macOS development tool that hijacks TCC's permission check inside running `tccd`
processes. It provides a timed bypass, status reporting, and readable logs showing
which process checked which permission and when.

## Requirements

- An Apple Silicon Mac. The injected library is built for `arm64e`, and the helper
  is built for `arm64`, with a macOS 15.0 deployment target.
- Xcode or a developer toolchain providing `xcrun clang`, LLDB with Python
  support, the macOS SDK, `make`, and `codesign`.
- Python 3.8 or later.
- A system configuration (SIP off) that permits debugger attachment to `tccd` and
  loading an ad-hoc-signed library into it. The tool does not change system security
  settings.

The implementation uses private TCC classes and methods, so compatibility
depends on the macOS version (verified on macOS 27.2). It checks the required hook
signatures when loaded.

## Build

From the project directory:

```sh
./tcc-bypass.py build
```

This invokes `make`, which builds and ad-hoc signs two files:

- `libtccd_inject.dylib`: the library loaded into each `tccd` process.
- `tccd_control_helper`: the resident broker and native command-line client.

You can also run `make` directly. To force a rebuild, use
`./tcc-bypass.py build --force` or `make -B`.

Build before starting the tool. Runtime commands use the existing binaries, and
they do not rebuild or reload them. Keep those binaries unchanged while in use.

## Usage

```sh
# Enable the bypass for the default 30 minutes.
./tcc-bypass.py start

# Enable or renew it for 10 minutes instead.
./tcc-bypass.py start 10

# Show the helper, connected tccd instances, expiry times, and log counters.
./tcc-bypass.py status

# Replay buffered logs, then follow live records. Ctrl-C stops the viewer.
./tcc-bypass.py logs

# Read the current log snapshot and exit.
./tcc-bypass.py logs --snapshot

# Disable the bypass immediately.
./tcc-bypass.py stop
```

Runtime commands request root access through `sudo` automatically. The duration
must be an integer from 1 to 1440 minutes. Repeating `start` reuses a healthy
helper and sets a new expiry, and it also reconnects missing `tccd` instances when
needed. `enable` and `disable` are aliases for `start` and `stop`.

The bypass is active only while its expiry is in the future and its injected
instance is connected to the helper. Closing the log viewer does not disable it.
`stop` disables the bypass but leaves the library loaded and the helper running.
The helper exits when its last connected `tccd` instance disconnects.

### Reading logs

Example output:

```text
2026-11-03 15:42:08.123 +0800  BYPASS  com.example.Recorder (PID 321) → Microphone [kTCCServiceMicrophone]
    binary: /Applications/Recorder.app/Contents/MacOS/Recorder
    responsible: com.example.Launcher (PID 99)
    TCC allow entitlement: supplied (originally absent) · tccd PID 123 · request Request-AbC
```

`BYPASS` means the hook supplied an entitlement result that was originally
absent. `CHECK` means it was already present, or the original result is unknown.
These records describe the hooked entitlement check, not the final outcome of
every permission request. Checks are logged only while the bypass is active.

By default, records with a **responsible** process identifier beginning with
`com.apple.` are hidden. Records without that identifier remain visible. This
is a client-side filter: `--all` also reveals matching records already buffered
by the helper.

Terminal output uses color. Redirected output is plain text, and `NO_COLOR`
disables color explicitly. `--json` preserves machine-readable replies, and the
default log filter still applies unless `--all` is also supplied.

Logs are held in a bounded, in-memory helper buffer and are lost when the helper
exits. Old records can be evicted.

## How it works

1. **Bootstrap:** `tcc-bypass.py` finds running `tccd` processes and verifies
   their executable paths. It uses LLDB to load the library, reads its readiness
   flag and Mach receive-port name, then starts or reconnects the native helper.
2. **Hooks:** the injected library replaces selected Objective-C method
   implementations inside `tccd`. While enabled, its `TCCDProcess` entitlement
   hook returns `YES` for `com.apple.private.tcc.allow`. Other entitlement checks
   keep their original results. Request-context and attribution-chain hooks capture
   process metadata and bind it to the request.
3. **Control:** the helper process communicates with injected instances over Mach
   ports, validates message audit tokens, coordinates timed enable/disable requests,
   and stores incoming logs in the ring buffer. Helper disconnection clears the
   injected instance's enabled state. The client helper sends commands to the broker
   helper and renders status and log messages. Python handles bootstrap and forwards
   public commands to the client helper.

The tool changes behavior in memory, and does not write permission grants to the
TCC database. The installed hooks remain until the affected `tccd` processes
exit, and use the original entitlement result whenever the bypass is inactive.

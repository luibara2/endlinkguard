# Modified Endstone runtime

A patch for [Endstone](https://github.com/EndstoneMC/endstone) that adds `PlayerPreLoginEvent`, plus
the tooling to apply it and rebuild the runtime.

**You only need this if you want the `modified/` build of EndlinkGuard.** The `stock/` build works on
official, unmodified Endstone and needs nothing from this directory.

## Why it exists

EndlinkGuard's job is to replace a proxied player's identity with the one the proxy verified. On
unmodified Endstone the earliest a plugin can act is `PlayerLoginEvent` — and by then BDS has already
chosen and loaded the native player-data record. The identity can be corrected for the plugin's own
purposes, but the world's inventory, scoreboard and Script API identity are already bound to whatever
BDS picked.

This patch adds an event that fires *before* that choice, so the verified XUID can be injected while
it still decides which record loads. That is what preserves XUID-owned inventory across a proxied
join.

The patch deliberately leaves the UUID alone. BDS keeps the world's established scoreboard and
Script API identity that way, and only the XUID needed correcting.

## What the patch changes

`src/patches/endstone-pre-login-identity.patch`, pinned to Endstone commit `39f5935f2`:

| File | Change |
| --- | --- |
| `include/endstone/event/player/player_pre_login_event.h` | New — the event itself |
| `include/endstone/endstone.hpp` | Exports the new header |
| `src/endstone/runtime/bedrock_hooks/server_network_handler.cpp` | Fires the event before BDS selects the player record |
| `src/endstone/python/event.cpp` | Exposes the event to Python |
| `endstone/event/__init__.py`, `__init__.pyi` | Python bindings and type stubs |

**Two of those are C++**, so this cannot be done by repacking a released wheel — Endstone's native
extension has to be rebuilt.

## Building it

### Prerequisites

Endstone's own, from its `CONTRIBUTING.md` — check there first, since they own this and it may move:

- **Linux:** Clang 18+ with libc++, CMake, Ninja, Conan 2.0+
- **Windows:** see Endstone's CONTRIBUTING; a Linux build is what the released wheels target
- Python 3.13 (the runtime targets CPython 3.13)

The released wheel this project was tested with is a **Linux CPython 3.13 manylinux** build. If your
backends run Linux — which BDS deployments generally do — build there.

### 1. Clone the pinned source and apply the patch

From this directory:

```powershell
git clone https://github.com/EndstoneMC/endstone.git .\build\endstone-source
git -C .\build\endstone-source checkout 39f5935f2662f2a063f79f9a2502e0f029d0e4e0
.\src\apply-endstone-patch.ps1 -EndstoneSource .\build\endstone-source
```

```bash
# same thing on Linux
git clone https://github.com/EndstoneMC/endstone.git build/endstone-source
git -C build/endstone-source checkout 39f5935f2662f2a063f79f9a2502e0f029d0e4e0
git -C build/endstone-source apply src/patches/endstone-pre-login-identity.patch
```

`apply-endstone-patch.ps1` refuses to run unless the checkout is at exactly that commit, and does a
`git apply --check` before touching anything. **That pin matters**: the patch edits a BDS hook whose
surrounding code moves between releases, so applying it to a different commit is how you get a build
that compiles and then misbehaves at runtime. If you need a newer Endstone, rebase the patch and
re-verify rather than forcing it.

### 2. Build the wheel

Endstone builds through Conan and a PEP 517 backend (`conan_py_build`), so a wheel is produced the
ordinary way from the patched source tree:

```bash
pip install conan
cd build/endstone-source
python -m build --wheel
```

Endstone ships a Conan profile at `.conan2/profiles/default` that detects your compiler. **Do not run
`conan profile detect`** — Endstone's own docs warn it overwrites that file.

Follow Endstone's `CONTRIBUTING.md` if any of this fails; the build is theirs, not ours, and these
steps are a summary of it rather than a replacement.

### 3. If you repacked the wheel on Windows

A Linux wheel rebuilt or repacked on Windows loses Unix file modes, and `endstone/crashpad_handler`
stops being executable — the server then fails at start in a way that does not obviously point back
here. Repair it against an official wheel:

```bash
python src/tools/restore-wheel-permissions.py <official-endstone.whl> <your-patched.whl>
```

It copies the modes across and refuses to finish unless `crashpad_handler` ends up executable.

## Using it

1. Install your patched wheel into the backend's Python environment, replacing the official Endstone.
2. Install **`endstone_endlinkguard-1.0.4-py3-none-any.whl`** (the `modified/` build) on that backend
   — not the stock one. Never both. If a pre-1.0.4 build is present, `pip uninstall endlinkguard`
   first: the old distribution name keeps its own entry point registered, and the loader logs
   "Invalid name" for it on every startup.
3. Configure `shared_secret` to match the proxy, as in the main README.

A backend running the patched runtime with the stock plugin simply loses the early-injection benefit.
A backend running official Endstone with the `modified/` plugin will fail: the event it needs does not
exist there.

## Licence

Endstone is licensed under the **Apache License 2.0**, and so is this patch and tooling. A build made
from this patch is a modified version of Endstone: if you distribute one, Apache 2.0 section 4
requires you to include Endstone's `LICENSE`, mark the files as changed, and say what you changed —
the table above is what changed.

No prebuilt patched wheel is distributed here, precisely because doing so takes on that redistribution
responsibility for someone else's compiled runtime. Build your own from the pinned commit.

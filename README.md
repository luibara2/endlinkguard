# EndlinkGuard

[![Build](https://github.com/luibara2/endlinkguard/actions/workflows/build.yml/badge.svg)](https://github.com/luibara2/endlinkguard/actions/workflows/build.yml)
[![Release](https://img.shields.io/github/v/release/luibara2/endlinkguard?include_prereleases&sort=semver)](https://github.com/luibara2/endlinkguard/releases)
[![Licence](https://img.shields.io/github/license/luibara2/endlinkguard)](LICENSE)
[![Endstone](https://img.shields.io/badge/Endstone-plugin-blue)](https://github.com/EndstoneMC/endstone)

The backend half of an Endlink network. It runs on each Endstone server and makes sure a player only
gets in if Endlink sent them.

An Endlink network puts every backend into offline mode so the proxy can own authentication. That is
what makes one session across many servers possible, and on its own it leaves each backend open to
anyone who learns its address. EndlinkGuard closes that: it verifies every join against the proxy
over an HMAC-signed handshake and rejects the rest.

By analogy: if Endlink is Velocity, EndlinkGuard is what modern forwarding plus Floodgate do on the
server side.

> ### Status: work in progress
>
> Under active development alongside [Endlink](https://github.com/luibara2/endlink). Expect rough
> edges, and expect things to change.
>
> **What is tested and working: Endstone on Minecraft 1.26.40, behind an Endlink proxy on 1.26.40.**
> Direct joins are rejected and proxied joins verified. Other versions are less certain.

## Which build to install

**Never install both on one backend.**

| Backend | Use | What you get |
| --- | --- | --- |
| Official, unmodified Endstone | `stock/` | Direct joins rejected, proxy joins verified, proxy-backed XUID available to Python plugins |
| Patched Endstone `0.11.7.post2` | `modified/` | All of the above, **plus** the verified XUID and UUID injected before BDS loads player data |

The difference matters for player data. Stock Endstone picks the native player record before
`PlayerLoginEvent`, which is the first point a plugin can act, so the stock build cannot preserve
XUID-owned inventory by itself. The patched runtime exposes `PlayerPreLoginEvent`, which is early
enough.

> **Start with `stock/`.** It installs onto official Endstone and needs nothing else.
>
> The `modified/` build additionally requires a **patched Endstone runtime that you build yourself** —
> no prebuilt one is distributed here. The patch changes C++ as well as Python, so it cannot be done
> by repacking a released wheel; Endstone's native extension has to be recompiled, realistically on
> Linux. `modified-endstone/` holds the patch, the pinned commit, the tooling and a full build guide:
> see [modified-endstone/README.md](modified-endstone/README.md).
>
> Installing `modified/` on official Endstone will fail — the event it needs does not exist there.

## Configuration

Both builds read `config.toml` from their plugin directory:

```toml
allowed_proxy_ips = ["127.0.0.1", "::1"]        # add the proxy's address if it is on another host
proxy_verify_url  = "http://127.0.0.1:19135/verify"
shared_secret     = "change-this-shared-secret"  # must equal Endlink's backendVerification.sharedSecret
```

The shared secret is the whole trust anchor. If it does not match the proxy's, every proxied join is
rejected and the server logs say so plainly rather than failing open.

## Building

Each project is a standard hatchling build:

```
cd stock      && python -m build --wheel
cd modified   && python -m build --wheel
```

The wheel lands in `dist/`. Install it on the backend and remove any older verifier wheel first — the
package name changed from `endstone-backend-verifier`, so pip will not replace it and Endstone would
otherwise try to load both plugins.

## Repository layout

```
stock/              EndlinkGuard for unmodified Endstone
modified/           EndlinkGuard for the patched runtime
modified-endstone/  The Endstone source patch, build tooling and prebuilt runtime wheel
```

## Licence

EndlinkGuard is licensed under the **Apache License 2.0** — see `LICENSE`. This matches
[Endstone](https://github.com/EndstoneMC/endstone) (also Apache 2.0), the server it is a plugin for.

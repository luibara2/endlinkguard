# Endstone backend verifier plugin

This Python plugin authenticates pending joins against the Java proxy's HMAC
verification endpoint and handles `PlayerPreLoginEvent` from the modified
Endstone runtime. It restores the verified XUID before native BDS player data
is loaded while preserving BDS's UUID so existing Script API, scoreboard, and
world-linked player identities continue to resolve.

Version `1.0.4` renames the distribution to `endstone-endlinkguard`. Endstone's
plugin loader requires the distribution name to be `endstone-` plus the entry
point name and refuses to load anything else, so 1.0.3 and earlier fail on
Endstone 0.11.7 with "Invalid name". Uninstall the old `endlinkguard`
distribution when upgrading — see the note below.

Version `1.0.3` fixed the split-identity regression caused by replacing BDS's
world UUID with the proxy login-chain UUID. Version `1.0.2` also added the
proxy-authenticated client endpoint through
Python's `Player.address` property. Existing plugins that read
`PlayerLoginEvent.player.address.hostname`, including EndstoneIpLogger, receive
the real client IP without a plugin-specific integration.

Run its protocol tests from this directory with:

```powershell
python -m unittest discover -s tests -v
```

Build a wheel into this project's artifact directory with:

```powershell
python -m pip wheel . --no-deps --wheel-dir dist
```

The current upload-ready plugin wheel is stored in this project's `dist/`.

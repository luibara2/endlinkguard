# Backend verifier for stock Endstone

This is the legacy `0.1.7` verifier for an **unmodified/official Endstone**
runtime. It verifies that backend joins came through endstone-proxy, stores the
proxy-returned identity, exposes `get_real_xuid()`, and preserves the legacy
proxy-backed operator store.

It also exposes the authenticated client endpoint through Python's
`Player.address` property. Plugins such as EndstoneIpLogger that read
`PlayerLoginEvent.player.address.hostname` therefore receive the real client IP
instead of the proxy's backend-facing IP. The override is live-session-only and
falls back to Endstone's native address until proxy verification succeeds.

Because stock Endstone emits `PlayerLoginEvent` after BDS selects its native
player record, this version cannot make BDS load inventory or other native data
under the verified XUID. Use `../modified-endstone-verifier` version `1.0.2`
together with `../modified-endstone` when native player-data continuity is
required.

Build from this directory with:

```powershell
python -m pip wheel . --no-deps --wheel-dir dist
```

The upload-ready stock-compatible wheel is kept in this project's `dist/`.

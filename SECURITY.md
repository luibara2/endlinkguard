# Security policy

## Reporting a vulnerability

**Please do not open a public issue for a security problem.**

Report it privately through GitHub's
[security advisory form](https://github.com/luibara2/endlinkguard/security/advisories/new). That opens
a channel only you and the maintainer can see, and lets a fix exist before the problem is public.

Tell me what you can: what the flaw allows, how to reproduce it, and which versions of EndlinkGuard,
Endstone and Minecraft you tested.

## Why this plugin matters for security

EndlinkGuard is the only thing standing between an offline-mode backend and the internet. An Endlink
network deliberately runs its backends in offline mode so the proxy can own authentication; this
plugin is what makes that safe, by verifying every join against the proxy and rejecting the rest.

A flaw here therefore means anyone can join a backend as anyone.

## What is in scope

- **Forging a verified join** — getting the plugin to accept a join the proxy never authorised,
  without knowing the shared secret.
- **Bypassing the direct-join rejection**, from an address that is not an allowed proxy.
- **Leaking the shared secret**, for example through a log line or an error message.
- **Identity confusion** — causing a player to be admitted under another player's XUID or UUID.
- **Weaknesses in the HMAC handshake itself**: replay, timing side channels, or signature checks that
  can be skipped.

## What is not

- A backend deliberately configured with `allowed_proxy_ips` open to the world, or a shared secret
  left at its `change-this-shared-secret` default. Both are misconfigurations the documentation warns
  about.
- Anything requiring local access to the backend, which already exposes the secret in `config.toml`.
- Bugs in Endstone, Bedrock Dedicated Server or Minecraft — report those upstream.
- The patched-runtime build process. A modified Endstone you compiled yourself is yours to trust.

## Supported versions

This is a work in progress with no long-term support branches. Fixes land on `main` and go out in the
next release. Only the latest release of each build is supported.

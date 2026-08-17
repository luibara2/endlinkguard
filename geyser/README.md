# EndlinkGuard for Geyser

The Geyser build of EndlinkGuard. Same job as the Endstone builds — a player only gets in if Endlink
sent them — for a [Geyser](https://geysermc.org) instance sitting between Endlink and a
Minecraft: Java server.

This is what lets an Endlink network include a **Java Edition backend**. Bedrock players join the
proxy as usual; Geyser translates their session to Java and hands it to Paper (or any Java server)
through Floodgate. From the proxy's point of view it is just another backend.

> ### Status: work in progress
>
> Newer and less proven than the Endstone builds. The handshake is byte-compatible with them and
> verified as such, but the surrounding deployment has not been running long.

## Why a Geyser instance needs a guard

Geyser normally validates every Bedrock login against Xbox Live. A login forged by a proxy is not
Xbox-signed, so the instance in front of a Java backend has to run with

```yaml
advanced:
  bedrock:
    validate-bedrock-login: false
```

which is Geyser's equivalent of putting a backend into offline mode. From that moment anything that
can reach the port may claim any identity, exactly as with an unguarded Endstone backend. Two things
close that, and this extension is the second:

1. The Bedrock listener binds **loopback**, so only the proxy's own machine can reach it.
2. Every join is checked against the proxy that claims to have sent it.

It also **restores the player's real IP**, which matters more here than on Endstone: without it every
proxied player reaches the Java server from the proxy's address, and one IP ban there takes out the
whole network at once.

## One proxy setting is required

A Geyser backend needs this in Endlink's config, and it is not optional:

```properties
backend.<name>.dropSubChunkRequests=true
```

A Bedrock client only asks for terrain one sub-chunk at a time because a server told it to, and BDS
does. That mode belongs to the client's session rather than to one backend, so it survives a switch
— and the proxy's handoff is deliberately seamless, so the client is never told the new server works
differently. Geyser does not implement the sub-chunk system, treats the requests as a protocol
violation, and drops the player mid-game:

```
[Geyser] luibara2 has disconnected from the Java server because of Invalid packet received!
IllegalPacketException: Client tried to send unused packet SubChunkRequestPacket!
```

The extension cannot fix that — by the time the packet reaches Geyser's decoder the connection is
already being torn down. The proxy has to withhold it.

## What it does not require

**No changes to Endlink's login handling.** Geyser can do the auth and IP jobs natively through
`use-waterdogpe-forwarding`, but only if the proxy sends WaterdogPE's `Waterdog_XUID` and
`Waterdog_IP` fields — which would mean patching Endlink's login forging. This extension takes the
same information from the `/verify` endpoint the proxy already runs, so the proxy is untouched.

Leave `use-waterdogpe-forwarding: false`. Turning it on as well refuses every join with
`Did not receive IP and xuid forwarded from the proxy!`.

## How a join is checked

Identical to `stock/`, field for field:

1. Source address must be in `allowed_proxy_ips`, else refuse.
2. `GET {proxy_verify_url}?xuid&uuid&name&address&timestamp&nonce&signature`, HMAC-SHA256 over
   `v1\n<xuid>\n<uuid>\n<name>\n<address>\n<timestamp>\n<nonce>`, lowercase hex.
3. `200` with `"status":"ok"` → allow, and apply `real_ip` / `real_port` from the response.
4. Anything else → refuse, and log which.

Endlink registers the pending join before it sends the login, and this runs at `SessionLoginEvent`,
which is later — so the ordering always holds. Pending joins are single-use with a short TTL on the
proxy side, so a captured request cannot be replayed into a second join.

## Installing

Three things have to be right, and two of them are easy to get subtly wrong. Start from a **fresh
Geyser config** if yours has been edited much — the settings below moved between Geyser versions, and
editing an old config by hand is how most of the time gets lost.

**1. Geyser's `config.yml`.** Note the nesting: `validate-bedrock-login` lives under
`advanced:` → `bedrock:`, *not* the top-level `bedrock:` section. Setting it there does nothing at
all, silently.

```yaml
bedrock:
  address: 127.0.0.1        # loopback unless the proxy is on another host
  port: 19132

java:
  auth-type: floodgate      # requires Floodgate on the Java server

advanced:
  bedrock:
    validate-bedrock-login: false     # under advanced -> bedrock
    use-waterdogpe-forwarding: false  # leave false; this extension does that job
```

**2. `EndlinkGuard.jar`** into Geyser's `extensions/` folder.

**3. Its config**, below — in particular `allowed_proxy_ips`, which defaults to loopback. If the
proxy is on a different host than Geyser, its address must be listed there or every proxied join is
turned away. The rejection log names the address it saw and the file to add it to.

On first run the extension writes `extensions/endlinkguard/config.properties`:

```properties
allowed_proxy_ips=127.0.0.1,0:0:0:0:0:0:0:1
proxy_verify_url=http://127.0.0.1:19135/verify
shared_secret=
request_timeout_millis=2000
apply_real_ip=true
```

`shared_secret` must equal Endlink's `backendVerification.sharedSecret`. A mismatch rejects every
join and says so in the log rather than failing open. Set `allowed_proxy_ips` to the proxy's address
when it is not on this machine.

## Building

```powershell
.\build.ps1 -GeyserJar <path-to-Geyser.jar>
.\build.ps1 -GeyserJar <...> -DeployTo <server>\extensions
```

Needs a JDK 21+. There is no Gradle and nothing is downloaded: every Geyser jar already carries the
whole extension API, so the build compiles straight against it.

`-GeyserJar` is whichever Geyser this will run on — `Geyser-Standalone.jar`, `Geyser-Spigot.jar`,
`Geyser-Velocity.jar`. Extensions are platform-agnostic and Geyser resolves `extensions/` from each
platform's own config folder, so the same source serves all of them.

Not currently built in CI: the workflow builds Python wheels, and a Java step would have to fetch a
Geyser jar to compile against first.

## The one fragile line

```java
session.getUpstream().setInetAddress(new InetSocketAddress(realIp, realPort));
```

`GeyserSession` is Geyser **internal**, not public API — the public `GeyserConnection` offers no way
to set an address. Extensions can reach internals because their class loader delegates to Geyser's,
so this is a compile-checked call rather than reflection, but it carries no compatibility promise.

**Rebuild against the new jar after a Geyser update.** Two ways it can break, both loud:

| Breakage | Symptom |
| --- | --- |
| Method moved or renamed | `build.ps1` fails to compile |
| Extension API major bump | Geyser refuses to load the jar and logs an API version error |

If the call throws at runtime the player is still let in — they are verified, only the address
forwarding failed — and the log says the extension may need rebuilding. Kicking a legitimate player
over a logging concern would be the worse outcome, but it must not pass silently either.

## Troubleshooting

| Symptom | Cause |
| --- | --- |
| `Please log into Xbox to join this server` | `validate-bedrock-login` is still true. Check the nesting — it belongs under `advanced:` → `bedrock:`, and setting it anywhere else does nothing |
| `Rejected direct join from <ip>` for the **proxy's** address | `allowed_proxy_ips` does not list the proxy. The message names the address and the file |
| `Proxy verification failed.` on every join | `shared_secret` does not match the proxy's `backendVerification.sharedSecret`, or the proxy is unreachable from here |
| `Did not receive IP and xuid forwarded from the proxy!` | `use-waterdogpe-forwarding` got turned on. Leave it false; this extension does that job |
| Joins work, but the Java server logs the proxy's IP for everyone | The extension could not apply the real address. Check the log and rebuild against the running Geyser |
| Geyser refuses to load the jar, logging an API version error | Geyser's extension API moved. Rebuild against the new jar |

Direct joins being refused is the extension working, not a fault — the only address that should get
in is the proxy's.

## Related

| | |
| --- | --- |
| [Endlink](https://github.com/luibara2/endlink) | **Required.** The proxy this verifies joins against |
| [Geyser](https://github.com/GeyserMC/Geyser) | The translator this extends. MIT licensed; only compiled against, never vendored here |
| [Floodgate](https://github.com/GeyserMC/Floodgate) | Needed on the Java server so Bedrock players get an identity |

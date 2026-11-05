"""Secure, pre-load identity forwarding for endstone-proxy backends.

This plugin targets the patched Endstone runtime shipped beside this project.
The patch fires PlayerPreLoginEvent after BDS parses the login but before it
chooses a PlayerStorageIds record. Supplying the proxy-verified XUID there makes
BDS load and save its original native record, including inventory and Ender
Chest, instead of creating an empty self-signed-player record. The UUID parsed
by BDS is deliberately preserved: replacing it with the proxy chain UUID can
detach the player from the world's existing Script API and scoreboard identity.
"""

import json
import time
from ipaddress import ip_address
from pathlib import Path

from endstone import Player
from endstone.event import (
    BlockBreakEvent,
    BlockPlaceEvent,
    EventPriority,
    PlayerGameModeChangeEvent,
    PlayerInteractActorEvent,
    PlayerInteractEvent,
    PlayerJoinEvent,
    PlayerLoginEvent,
    PlayerMoveEvent,
    PlayerPreLoginEvent,
    PlayerQuitEvent,
    event_handler,
)
from endstone.plugin import Plugin

from endlinkguard.verification import (
    VerificationError,
    VerifiedIdentity,
    verify_pending_join,
)


_REAL_ADDRESS_PROVIDERS = []
_ADDRESS_PATCH_INSTALLED = False
_ORIGINAL_PLAYER_ADDRESS = None


class _ForwardedSocketAddress:
    """SocketAddress-compatible Python view of the verified client endpoint."""

    __slots__ = ("hostname", "port")

    def __init__(self, hostname: str, port: int) -> None:
        self.hostname = str(hostname)
        self.port = int(port)

    @property
    def host(self) -> str:
        return self.hostname

    @property
    def address(self) -> str:
        return self.hostname

    def __str__(self) -> str:
        host = f"[{self.hostname}]" if ":" in self.hostname else self.hostname
        return f"{host}:{self.port}" if self.port else host


def _patched_player_address(player: Player):
    name = ""
    try:
        name = str(player.name)
    except Exception:
        pass
    if name:
        for plugin in _REAL_ADDRESS_PROVIDERS:
            try:
                endpoint = plugin._proxy_address(name)
            except Exception:
                continue
            if endpoint is not None:
                return endpoint
    if _ORIGINAL_PLAYER_ADDRESS is None:
        return None
    try:
        return _ORIGINAL_PLAYER_ADDRESS.__get__(player, type(player))
    except Exception:
        return None


def _install_address_patch(logger) -> None:
    global _ADDRESS_PATCH_INSTALLED, _ORIGINAL_PLAYER_ADDRESS
    if _ADDRESS_PATCH_INSTALLED:
        return
    try:
        _ORIGINAL_PLAYER_ADDRESS = Player.__dict__.get("address")
        Player.address = property(_patched_player_address)
        _ADDRESS_PATCH_INSTALLED = True
        logger.info("Patched Player.address to expose proxy-verified client addresses.")
    except Exception as exc:
        logger.warning(
            f"Unable to monkey-patch Player.address ({exc}); "
            "use EndlinkGuardPlugin.get_real_address() instead."
        )


class EndlinkGuardPlugin(Plugin):
    # Keep the original plugin name/data folder so proxy-identities.json and
    # proxy-permissions.json from verifier 0.1.x remain available.
    name = "endlinkguard"
    version = "1.2.1"
    api_version = "0.10"
    description = "Restores proxy player XUID before BDS loads native player data."

    def on_enable(self) -> None:
        self.save_default_config()
        self._approved: dict[str, tuple[VerifiedIdentity, float]] = {}
        self._verified_addresses: dict[str, VerifiedIdentity] = {}
        self._identity_store = self._load_json(
            "proxy-identities.json", {"version": 2, "players": {}}
        )
        self._permission_store = self._load_json(
            "proxy-permissions.json", {"version": 1, "players": {}}
        )
        self.register_events(self)
        if self.config.get("shared_secret") == "change-this-shared-secret":
            self.logger.warning("shared_secret is still the default development value.")
        if self._debug_enabled():
            self.logger.info("Backend interaction debug logging enabled.")
        self.logger.info(
            "Pre-load proxy identity forwarding enabled; BDS native player data will use the verified XUID."
        )
        if self not in _REAL_ADDRESS_PROVIDERS:
            _REAL_ADDRESS_PROVIDERS.append(self)
        if self._apply_real_ip():
            _install_address_patch(self.logger)
        else:
            self.logger.warning(
                "apply_real_ip is off; Player.address will report this proxy's address for every "
                "player, so anything that bans or rate-limits by IP will act on all of them at once."
            )

    def on_disable(self) -> None:
        try:
            _REAL_ADDRESS_PROVIDERS.remove(self)
        except ValueError:
            pass

    def get_real_xuid(self, player_or_name) -> str:
        """Return a stored proxy-verified XUID for compatibility with 0.1.x."""
        name = getattr(player_or_name, "name", player_or_name)
        record = self._identity_for_name(str(name))
        return "" if not record else str(record.get("xuid", ""))

    def get_real_address(self, player_or_name):
        """Return the current proxy-verified SocketAddress-compatible endpoint."""
        if player_or_name is None:
            return None
        name = getattr(player_or_name, "name", player_or_name)
        return self._proxy_address(str(name))

    def get_real_ip(self, player_or_name) -> str:
        endpoint = self.get_real_address(player_or_name)
        return "" if endpoint is None else endpoint.hostname

    @event_handler(priority=EventPriority.LOWEST)
    def on_player_pre_login(self, event: PlayerPreLoginEvent) -> None:
        """Authenticate and inject identity before tryToLoadPlayer runs."""
        self._prune_approvals()
        try:
            source_ip = _extract_ip(event.address)
            allowed = {
                str(ip_address(value))
                for value in self.config.get("allowed_proxy_ips", [])
            }
        except ValueError as exc:
            self._reject(event, "Backend identity configuration is invalid.")
            self.logger.error(f"Invalid proxy address configuration or source address: {exc}")
            return

        if source_ip not in allowed:
            self._reject(event, "Please connect through the proxy.")
            self.logger.warning(
                f"Rejected direct backend pre-login from {source_ip} as {event.name}."
            )
            return

        try:
            identity = verify_pending_join(
                str(self.config["proxy_verify_url"]),
                str(self.config["shared_secret"]),
                name=str(event.name),
                address=source_ip,
                xuid=str(event.xuid or ""),
                unique_id=str(event.unique_id or ""),
                timeout=float(self.config.get("request_timeout_seconds", 2.0)),
            )
        except VerificationError as exc:
            self._reject(event, "Proxy verification failed.")
            self.logger.warning(
                f"Rejected unverified backend pre-login for {event.name} from {source_ip}: {exc}"
            )
            return

        # Restore only the verified XUID. BDS owns authenticated_uuid and uses it
        # together with PlayerStorageIds to retain the world's established player
        # identity. Injecting the proxy chain UUID here preserves inventory via
        # XUID but creates a second UUID identity for scoreboard/Script API data.
        backend_uuid = str(event.unique_id or "")
        event.xuid = identity.xuid
        self._approved[_name_key(identity.name)] = (
            identity,
            time.monotonic() + self._approval_timeout(),
        )
        self.logger.info(
            f"Restored proxy-verified XUID before player-data load: name={identity.name} "
            f"xuid={identity.xuid} preserved_backend_uuid={backend_uuid} "
            f"proxy_uuid={identity.unique_id} backend={identity.backend}."
        )

    @event_handler(priority=EventPriority.LOWEST)
    def on_player_login(self, event: PlayerLoginEvent) -> None:
        """Fail closed if a player somehow reaches the normal login event unapproved."""
        key = _name_key(event.player.name)
        self._verified_addresses.pop(key, None)
        approval = self._approved.pop(key, None)
        if approval is None:
            self._reject(event, "Proxy verification was not completed.")
            self.logger.warning(f"Rejected login without pre-load approval: {event.player.name}.")
            return

        identity, expires_at = approval
        if expires_at < time.monotonic():
            self._reject(event, "Proxy verification expired.")
            self.logger.warning(
                f"Rejected {event.player.name}: the proxy-verified approval from pre-login expired "
                f"after {self._approval_timeout():.0f}s before BDS reached the login event. "
                "Raise approval_timeout_seconds if joins on this backend legitimately take longer."
            )
            return

        actual_xuid = str(event.player.xuid or "")
        actual_uuid = str(event.player.unique_id or "")
        if actual_xuid != identity.xuid:
            self._reject(event, "Backend identity injection failed.")
            self.logger.error(
                f"BDS identity mismatch after injection for {event.player.name}: "
                f"expected xuid={identity.xuid}, got xuid={actual_xuid!r} "
                f"backend_uuid={actual_uuid!r}."
            )
            return

        record = {
            "name": identity.name,
            "xuid": identity.xuid,
            # The BDS/world UUID is intentionally distinct from the proxy login
            # chain UUID on modern offline backends. Keep both for diagnostics.
            "uuid": actual_uuid,
            "proxy_uuid": identity.unique_id,
            "backend": identity.backend,
            "verified_at": str(int(time.time() * 1000)),
        }
        self._identity_store.setdefault("players", {})[key] = record
        self._save_json("proxy-identities.json", self._identity_store)
        self._verified_addresses[key] = identity

    @event_handler(priority=EventPriority.MONITOR)
    def on_player_quit(self, event: PlayerQuitEvent) -> None:
        self._verified_addresses.pop(_name_key(event.player.name), None)

    @event_handler
    def on_player_join(self, event: PlayerJoinEvent) -> None:
        if not bool(self.config.get("restore_legacy_operator_store", True)):
            return
        record = self._stored_permission_record(event.player.name)
        if not record or not bool(record.get("op")) or event.player.is_op:
            return
        try:
            _grant_operator(self.server, event.player)
            self.logger.info(
                f"Restored legacy proxy-persisted operator status for {event.player.name}."
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to restore operator status for {event.player.name}: {exc}"
            )

    # ------------------------------------------------------------------ debug
    # Identical in the stock build, and gated by the same two config keys, so a report from either
    # backend reads the same. Off by default: these fire on every interaction and every movement.

    @event_handler
    def on_game_mode_change(self, event: PlayerGameModeChangeEvent) -> None:
        if self._debug_enabled():
            self.logger.info(
                f"debug gamemode name={event.player.name} "
                f"new={event.new_game_mode} cancelled={event.cancelled}"
            )

    @event_handler
    def on_player_interact(self, event: PlayerInteractEvent) -> None:
        if self._debug_enabled():
            self.logger.info(
                f"debug interact name={event.player.name} action={event.action} "
                f"has_block={event.has_block} block={_safe_attr(event, 'block')} "
                f"face={_safe_attr(event, 'block_face')} has_item={event.has_item} "
                f"item={_safe_attr(event, 'item')} cancelled={event.cancelled}"
            )

    @event_handler
    def on_player_interact_actor(self, event: PlayerInteractActorEvent) -> None:
        if self._debug_enabled():
            self.logger.info(
                f"debug interact_actor name={event.player.name} "
                f"actor={_safe_attr(event, 'actor')} cancelled={event.cancelled}"
            )

    @event_handler
    def on_block_break(self, event: BlockBreakEvent) -> None:
        if self._debug_enabled():
            self.logger.info(
                f"debug block_break name={event.player.name} block={event.block} "
                f"game_mode={_safe_attr(event.player, 'game_mode')} "
                f"cancelled={event.cancelled}"
            )

    @event_handler
    def on_block_place(self, event: BlockPlaceEvent) -> None:
        if self._debug_enabled():
            self.logger.info(
                f"debug block_place name={event.player.name} block={event.block} "
                f"against={_safe_attr(event, 'block_against')} "
                f"game_mode={_safe_attr(event.player, 'game_mode')} "
                f"cancelled={event.cancelled}"
            )

    @event_handler
    def on_player_move(self, event: PlayerMoveEvent) -> None:
        if not self._debug_enabled() or not self.config.get("debug_movement", False):
            return
        self.logger.info(
            f"debug move name={event.player.name} from={event.from_location} "
            f"to={event.to_location} cancelled={event.cancelled}"
        )

    def _apply_real_ip(self) -> bool:
        """Whether Player.address should report the player's real endpoint.

        Same key, same default and same meaning in all three builds. Turning it off leaves every
        proxied player sharing the proxy's address, so one IP ban downstream hits the whole network -
        it exists to isolate a suspected fault in the address handling, not as a normal setting. The
        get_real_address()/get_real_ip() API keeps working either way; only the patch is skipped.
        """
        return bool(self.config.get("apply_real_ip", True))

    def _debug_enabled(self) -> bool:
        return bool(self.config.get("debug_interactions", False))

    def _approval_timeout(self) -> float:
        """Seconds a pre-login approval stays usable before its player must verify again.

        BDS fires PlayerPreLoginEvent when it parses the login and PlayerLoginEvent only once the
        client is ready to enter the world, and everything in between counts against this: the
        client's resource pack download most of all. Endlink keeps the backend connection open and
        waiting through that download, so a player pulling several megabytes of packs over a slow
        link is inside this window the whole time.

        This was a hard-coded 15 seconds, which a pack download beats routinely and a slow player
        data load beats occasionally. Both showed up as "Proxy verification expired." — the player
        read it as a random kick, because from their side it was one.

        The window is not what keeps an unverified player out. on_player_pre_login runs first for
        every login, rejects anything that is not from an allowed proxy address, and re-verifies
        through the proxy before writing an approval at all; a cancelled pre-login means no login
        event follows. This bound only stops abandoned approvals from lingering, so it can afford to
        be generous.
        """
        try:
            timeout = float(self.config.get("approval_timeout_seconds", 600.0))
        except (TypeError, ValueError):
            self.logger.warning(
                "approval_timeout_seconds is not a number; falling back to 600."
            )
            return 600.0
        return timeout if timeout > 0 else 600.0

    def _prune_approvals(self) -> None:
        now = time.monotonic()
        self._approved = {
            key: value for key, value in self._approved.items() if value[1] >= now
        }

    def _stored_permission_record(self, name: str) -> dict | None:
        players = self._permission_store.get("players", {})
        identity = self._identity_for_name(name)
        if identity and str(identity.get("xuid", "")).strip():
            record = players.get("xuid:" + str(identity["xuid"]).strip())
            if record:
                return record
        return players.get("name:" + _name_key(name))

    def _identity_for_name(self, name: str) -> dict | None:
        return self._identity_store.get("players", {}).get(_name_key(name))

    def _proxy_address(self, name: str):
        identity = self._verified_addresses.get(_name_key(name))
        if identity is None or not identity.real_ip:
            return None
        return _ForwardedSocketAddress(identity.real_ip, identity.real_port)

    def _load_json(self, filename: str, fallback: dict) -> dict:
        path = Path(self.data_folder) / filename
        try:
            if path.exists():
                with path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                return data if isinstance(data, dict) else fallback.copy()
        except Exception as exc:
            self.logger.warning(f"Unable to load {path}: {exc}")
        return fallback.copy()

    def _save_json(self, filename: str, data: dict) -> None:
        path = Path(self.data_folder) / filename
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".tmp")
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, sort_keys=True)
                file.write("\n")
            temporary.replace(path)
        except Exception as exc:
            self.logger.warning(f"Unable to save {path}: {exc}")

    @staticmethod
    def _reject(event, message: str) -> None:
        try:
            event.kick_message = message
        except Exception:
            pass
        event.cancel()


def _safe_attr(obj: object, attr: str):
    try:
        return getattr(obj, attr)
    except Exception as exc:
        return f"<error {exc}>"


def _grant_operator(server, player) -> None:
    name = str(player.name).replace('"', "")
    try:
        dispatched = bool(server.dispatch_command(server.command_sender, f'op "{name}"'))
    except Exception:
        dispatched = False
    if not dispatched or _safe_attr(player, "is_op") is not True:
        player.is_op = True
    try:
        player.update_commands()
    except Exception:
        pass

def _name_key(name: str) -> str:
    return str(name).casefold()


def _extract_ip(address: object) -> str:
    for attr in ("hostname", "host", "address"):
        value = getattr(address, attr, None)
        if value:
            return str(ip_address(str(value).strip("/[]")))

    text = str(address).strip().lstrip("/")
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif ":" in text:
        text = text.rsplit(":", 1)[0]
    return str(ip_address(text))


__all__ = ["EndlinkGuardPlugin"]

import json
import re
import time
from ipaddress import ip_address
from pathlib import Path

from endstone import Player
from endstone.event import (
    BlockBreakEvent,
    BlockPlaceEvent,
    EventPriority,
    PlayerCommandEvent,
    PlayerGameModeChangeEvent,
    PlayerInteractActorEvent,
    PlayerInteractEvent,
    PlayerJoinEvent,
    PlayerLoginEvent,
    PlayerMoveEvent,
    PlayerQuitEvent,
    ServerCommandEvent,
    event_handler,
)
from endstone.plugin import Plugin

from endlinkguard.verification import (
    VerificationError,
    VerifiedIdentity,
    verify_pending_join,
)


# Live instances that can supply a verified XUID for a player name. A registry
# keeps the descriptor usable after an Endstone plugin reload.
_VERIFIED_XUID_PROVIDERS = []
_XUID_PATCH_INSTALLED = False
_ORIGINAL_PLAYER_XUID = None
_ADDRESS_PATCH_INSTALLED = False
_ORIGINAL_PLAYER_ADDRESS = None


class _ForwardedSocketAddress:
    """SocketAddress-compatible Python view of the proxy-verified client endpoint."""

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


def _patched_player_xuid(player: Player) -> str:
    """Prefer the proxy-verified XUID, then fall back to Endstone's value."""
    name = ""
    try:
        name = str(player.name)
    except Exception:
        pass
    if name:
        for plugin in _VERIFIED_XUID_PROVIDERS:
            try:
                verified = plugin._proxy_xuid(name)
            except Exception:
                continue
            if verified:
                return verified
    if _ORIGINAL_PLAYER_XUID is None:
        return ""
    try:
        return _ORIGINAL_PLAYER_XUID.__get__(player, type(player)) or ""
    except Exception:
        return ""


def _install_xuid_patch(logger) -> None:
    """Best-effort Python-side XUID override for stock Endstone."""
    global _XUID_PATCH_INSTALLED, _ORIGINAL_PLAYER_XUID
    if _XUID_PATCH_INSTALLED:
        return
    try:
        _ORIGINAL_PLAYER_XUID = Player.__dict__.get("xuid")
        Player.xuid = property(_patched_player_xuid)
        _XUID_PATCH_INSTALLED = True
        logger.info("Patched Player.xuid to source from proxy-verified identity store.")
    except Exception as exc:
        logger.warning(
            f"Unable to monkey-patch Player.xuid ({exc}); "
            "use EndlinkGuardPlugin.get_real_xuid() instead."
        )


def _patched_player_address(player: Player):
    """Prefer the current proxy-verified client endpoint for Python plugins."""
    name = ""
    try:
        name = str(player.name)
    except Exception:
        pass
    if name:
        for plugin in _VERIFIED_XUID_PROVIDERS:
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
    """Expose the authenticated real client IP through Player.address."""
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
    name = "endlinkguard"
    version = "1.2.1"
    api_version = "0.10"
    description = "Rejects direct backend joins unless endstone-proxy verifies the login."

    def on_enable(self) -> None:
        self.save_default_config()
        self._verified_players = {}
        self._operator_restore_sessions = {}
        self._identity_store = self._load_json(
            "proxy-identities.json", {"version": 1, "players": {}}
        )
        self._permission_store = self._load_json(
            "proxy-permissions.json", {"version": 1, "players": {}}
        )
        self.register_events(self)
        if self.config.get("shared_secret") == "change-this-shared-secret":
            self.logger.warning("shared_secret is still the default development value.")
        self.logger.info("Backend join verification enabled.")
        if self._permission_store_enabled():
            self.logger.info("Proxy-backed permission persistence enabled.")
        if self._debug_enabled():
            self.logger.info("Backend interaction debug logging enabled.")
        if self not in _VERIFIED_XUID_PROVIDERS:
            _VERIFIED_XUID_PROVIDERS.append(self)
        _install_xuid_patch(self.logger)
        if self._apply_real_ip():
            _install_address_patch(self.logger)
        else:
            self.logger.warning(
                "apply_real_ip is off; Player.address will report this proxy's address for every "
                "player, so anything that bans or rate-limits by IP will act on all of them at once."
            )

    def on_disable(self) -> None:
        try:
            _VERIFIED_XUID_PROVIDERS.remove(self)
        except ValueError:
            pass

    def get_real_xuid(self, player_or_name) -> str:
        """Return the stored proxy-verified XUID for a player or name."""
        if player_or_name is None:
            return ""
        name = getattr(player_or_name, "name", player_or_name)
        return self._proxy_xuid(str(name))

    def get_real_address(self, player_or_name):
        """Return the current proxy-verified SocketAddress-compatible endpoint."""
        if player_or_name is None:
            return None
        name = getattr(player_or_name, "name", player_or_name)
        return self._proxy_address(str(name))

    def get_real_ip(self, player_or_name) -> str:
        """Return the current proxy-verified client IP without the source port."""
        endpoint = self.get_real_address(player_or_name)
        return "" if endpoint is None else endpoint.hostname

    @event_handler(priority=EventPriority.LOWEST)
    def on_player_login(self, event: PlayerLoginEvent) -> None:
        player = event.player
        # Never let a previous session with the same name affect verification of
        # this socket. Until the proxy approves this login, Player.address must
        # resolve to Endstone's native backend-facing address.
        self._verified_players.pop(_name_key(player.name), None)
        source_ip = _extract_ip(player.address)

        allowed_proxy_ips = {
            str(ip_address(value))
            for value in self.config.get("allowed_proxy_ips", [])
        }
        if source_ip not in allowed_proxy_ips:
            self._reject(event, "Please connect through the proxy.")
            self.logger.warning(
                f"Rejected direct backend join from {source_ip} as {player.name}."
            )
            return

        try:
            identity = verify_pending_join(
                str(self.config["proxy_verify_url"]),
                str(self.config["shared_secret"]),
                name=str(player.name),
                address=source_ip,
                xuid=str(player.xuid or ""),
                unique_id=str(player.unique_id or ""),
                timeout=float(self.config.get("request_timeout_seconds", 2.0)),
            )
        except VerificationError as exc:
            # Anything the shared module refuses is refused here too, including a 200 whose body is
            # not an identity this plugin can vouch for. That response is not authenticated - only
            # the request is - and the address it carries becomes Player.address, which IP logging
            # and bans downstream read as fact.
            self._reject(event, "Proxy verification failed.")
            self.logger.warning(
                f"Rejected unverified backend join for {player.name} "
                f"(xuid={player.xuid!r} uuid={player.unique_id!r}): {exc}"
            )
            return

        self._remember_verified_player(identity)

    @event_handler
    def on_player_join(self, event: PlayerJoinEvent) -> None:
        self._schedule_stored_permissions_restore(event.player)
        if not self._debug_enabled():
            return
        player = event.player
        self.logger.info(
            f"debug join name={player.name} xuid={player.xuid} "
            f"proxy_xuid={self._proxy_xuid(player.name)} "
            f"runtime_id={_safe_attr(player, 'runtime_id')} "
            f"game_mode={_safe_attr(player, 'game_mode')} "
            f"op={_safe_attr(player, 'is_op')} "
            f"permission={_safe_attr(player, 'permission_level')} "
            f"location={_safe_attr(player, 'location')} "
            f"dimension={_safe_attr(player, 'dimension')}"
        )

    @event_handler(priority=EventPriority.MONITOR)
    def on_player_quit(self, event: PlayerQuitEvent) -> None:
        key = _name_key(event.player.name)
        self._verified_players.pop(key, None)
        self._operator_restore_sessions.pop(key, None)

    @event_handler(priority=EventPriority.MONITOR)
    def on_server_command(self, event: ServerCommandEvent) -> None:
        if not event.is_cancelled:
            self._snapshot_permissions_after_op_command(event.command)

    @event_handler(priority=EventPriority.MONITOR)
    def on_player_command(self, event: PlayerCommandEvent) -> None:
        if not event.is_cancelled:
            self._snapshot_permissions_after_op_command(event.command)

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

    def _permission_store_enabled(self) -> bool:
        return bool(self.config.get("proxy_permission_store_enabled", True))

    def _remember_verified_player(self, verified: VerifiedIdentity) -> None:
        """Records an identity the shared module has already validated.

        Every field here has been through verify_pending_join: the name matches the one this plugin
        asked about, the XUID is digits, the UUID parses, and the endpoint is a real address in a
        legal port range. There is nothing left to salvage or second-guess, so unlike the previous
        version this cannot half-accept a malformed response and carry on.
        """
        name = verified.name
        identity = {
            "name": str(name),
            "xuid": verified.xuid,
            "uuid": verified.unique_id,
            "backend": verified.backend,
            "real_ip": verified.real_ip,
            "real_port": verified.real_port,
            "verified_at": str(int(time.time() * 1000)),
        }

        key = _name_key(name)
        self._verified_players[key] = identity
        # The endpoint is live connection data, not identity data. IpLogger may
        # persist it according to its own policy; the verifier deliberately does
        # not add a second long-lived IP history to proxy-identities.json.
        stored_identity = {
            field: value
            for field, value in identity.items()
            if field not in {"real_ip", "real_port"}
        }
        self._identity_store.setdefault("players", {})[key] = stored_identity
        self._save_json("proxy-identities.json", self._identity_store)

    def _schedule_stored_permissions_restore(self, player) -> None:
        if not self._permission_store_enabled():
            return
        record = self._stored_permission_record(player.name)
        if not record or not bool(record.get("op")):
            self.logger.info(
                f"No proxy-persisted operator record for {player.name} "
                f"(identity={'yes' if self._identity_for_name(player.name) else 'no'}, "
                f"stored_keys={len(self._permission_store.get('players', {}))}); "
                "leaving permissions as-is."
            )
            return
        key = _name_key(player.name)
        session = object()
        self._operator_restore_sessions[key] = session
        self.server.scheduler.run_task(
            self, lambda: self._restore_stored_permissions(key, session), delay=20
        )

    def _restore_stored_permissions(self, key, session) -> None:
        if self._operator_restore_sessions.get(key) is not session:
            return
        self._operator_restore_sessions.pop(key, None)
        player = next(
            (player for player in self.server.online_players if _name_key(player.name) == key),
            None,
        )
        if player is None:
            return
        record = self._stored_permission_record(player.name)
        if not record or not bool(record.get("op")):
            return
        try:
            if _safe_attr(player, "is_op") is True:
                name = str(player.name).replace('"', "")
                self.server.dispatch_command(self.server.command_sender, f'deop "{name}"')
            _grant_operator(self.server, player)
            self.logger.info(
                f"Restored proxy-persisted operator status for {player.name} "
                f"(proxy_xuid={record.get('xuid', '')})."
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to restore operator status for {player.name}: {exc}"
            )

    def _snapshot_permissions_after_op_command(self, command: str) -> None:
        if not self._permission_store_enabled():
            return
        if _command_name(command) not in {"op", "deop"}:
            return
        self.server.scheduler.run_task(
            self, self._snapshot_online_operator_state, delay=1
        )

    def _snapshot_online_operator_state(self) -> None:
        changed = False
        players = self._permission_store.setdefault("players", {})
        for player in self.server.online_players:
            identity = self._identity_for_name(player.name) or {}
            if not identity:
                self.logger.warning(
                    f"No proxy identity for {player.name} while snapshotting operator "
                    "state; persisting under the name key only."
                )
            keys = {"name:" + _name_key(player.name)}
            if str(identity.get("xuid", "")).strip():
                keys.add(_identity_key(identity, player.name))
            if _safe_attr(player, "is_op") is True:
                record = {
                    "name": str(player.name),
                    "xuid": str(identity.get("xuid", "")),
                    "uuid": str(identity.get("uuid", "")),
                    "op": True,
                    "updated_at": str(int(time.time() * 1000)),
                }
                for key in keys:
                    players[key] = dict(record)
                changed = True
            else:
                for key in keys:
                    if key in players:
                        del players[key]
                        changed = True
        if changed:
            self._save_json("proxy-permissions.json", self._permission_store)

    def _stored_permission_record(self, name: str):
        identity = self._identity_for_name(name)
        players = self._permission_store.get("players", {})
        if identity:
            record = players.get(_identity_key(identity, name))
            if record:
                return record
        return players.get("name:" + _name_key(name))

    def _identity_for_name(self, name: str):
        key = _name_key(name)
        return self._verified_players.get(key) or self._identity_store.get(
            "players", {}
        ).get(key)

    def _proxy_xuid(self, name: str) -> str:
        identity = self._identity_for_name(name)
        return "" if not identity else str(identity.get("xuid", ""))

    def _proxy_address(self, name: str):
        # Addresses are deliberately live-session-only. Reusing an endpoint
        # persisted from a previous login would poison direct-join checks and
        # give IP loggers stale data.
        identity = self._verified_players.get(_name_key(name))
        if not identity:
            return None
        real_ip = str(identity.get("real_ip") or "").strip()
        if not real_ip:
            return None
        return _ForwardedSocketAddress(real_ip, int(identity.get("real_port") or 0))

    def _load_json(self, filename: str, fallback: dict) -> dict:
        path = self._data_path(filename)
        try:
            if path.exists():
                with path.open("r", encoding="utf-8") as file:
                    data = json.load(file)
                    return data if isinstance(data, dict) else fallback.copy()
        except Exception as exc:
            self.logger.warning(f"Unable to load {path}: {exc}")
        return fallback.copy()

    def _save_json(self, filename: str, data: dict) -> None:
        path = self._data_path(filename)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            temporary = path.with_suffix(path.suffix + ".tmp")
            with temporary.open("w", encoding="utf-8") as file:
                json.dump(data, file, indent=2, sort_keys=True)
                file.write("\n")
            temporary.replace(path)
        except Exception as exc:
            self.logger.warning(f"Unable to save {path}: {exc}")

    def _data_path(self, filename: str) -> Path:
        return Path(self.data_folder) / filename

    @staticmethod
    def _reject(event: PlayerLoginEvent, message: str) -> None:
        try:
            event.kick_message = message
        except Exception:
            pass
        event.cancel()


def _name_key(name: str) -> str:
    return str(name).casefold()


def _identity_key(identity: dict, name: str) -> str:
    xuid = str(identity.get("xuid", "")).strip()
    return "xuid:" + xuid if xuid else "name:" + _name_key(name)


def _command_name(command: str) -> str:
    parts = re.split(r"\s+", str(command).strip().lstrip("/"), maxsplit=1)
    return parts[0].casefold() if parts and parts[0] else ""


def _extract_ip(address: object) -> str:
    for attr in ("host", "hostname", "address"):
        value = getattr(address, attr, None)
        if value:
            return str(ip_address(str(value).strip("/[]")))

    text = str(address).strip()
    if text.startswith("/"):
        text = text[1:]
    if text.startswith("["):
        text = text[1:].split("]", 1)[0]
    elif ":" in text:
        text = text.rsplit(":", 1)[0]
    return str(ip_address(text))


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

__all__ = ["EndlinkGuardPlugin"]

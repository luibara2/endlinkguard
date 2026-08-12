import hashlib
import hmac
import json
import re
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
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
    version = "0.1.7"
    api_version = "0.10"
    description = "Rejects direct backend joins unless endstone-proxy verifies the login."

    def on_enable(self) -> None:
        self.save_default_config()
        self._verified_players = {}
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
        if self.config.get("debug_interactions", False):
            self.logger.info("Backend interaction debug logging enabled.")
        if self not in _VERIFIED_XUID_PROVIDERS:
            _VERIFIED_XUID_PROVIDERS.append(self)
        _install_xuid_patch(self.logger)
        _install_address_patch(self.logger)

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

        request = {
            "xuid": str(player.xuid),
            "uuid": str(player.unique_id),
            "name": str(player.name),
            "address": source_ip,
            "timestamp": str(int(time.time() * 1000)),
            "nonce": uuid.uuid4().hex,
        }
        request["signature"] = _signature(self.config["shared_secret"], request)

        verify_url = self.config["proxy_verify_url"] + "?" + urllib.parse.urlencode(request)
        try:
            with urllib.request.urlopen(
                verify_url,
                timeout=float(self.config.get("request_timeout_seconds", 2.0)),
            ) as response:
                if response.status == 200:
                    body = response.read().decode("utf-8", "replace")
                    self._remember_verified_player(player.name, body, request)
                    return
                body = response.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as exc:
            try:
                body = f"HTTP {exc.code}: {exc.read().decode('utf-8', 'replace')}"
            except Exception:
                body = str(exc)
        except Exception as exc:
            body = str(exc)

        self._reject(event, "Proxy verification failed.")
        self.logger.warning(
            f"Rejected unverified backend join for {player.name} "
            f"(xuid={player.xuid!r} uuid={player.unique_id!r}): {body}"
        )

    @event_handler
    def on_player_join(self, event: PlayerJoinEvent) -> None:
        self._restore_stored_permissions(event.player)
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
        self._verified_players.pop(_name_key(event.player.name), None)

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

    def _debug_enabled(self) -> bool:
        return bool(self.config.get("debug_interactions", False))

    def _permission_store_enabled(self) -> bool:
        return bool(self.config.get("proxy_permission_store_enabled", True))

    def _remember_verified_player(self, name, response_body, request) -> None:
        identity = {
            "name": str(name),
            "xuid": request.get("xuid", ""),
            "uuid": request.get("uuid", ""),
            "backend": "",
            "real_ip": "",
            "real_port": 0,
            "verified_at": str(int(time.time() * 1000)),
        }
        try:
            payload = json.loads(response_body) if response_body.strip().startswith("{") else {}
            if isinstance(payload, dict):
                identity["xuid"] = str(payload.get("xuid") or identity["xuid"])
                identity["uuid"] = str(payload.get("uuid") or identity["uuid"])
                identity["backend"] = str(payload.get("backend") or "")
                real_ip = str(payload.get("real_ip") or "").strip()
                if real_ip:
                    identity["real_ip"] = str(ip_address(real_ip))
                real_port = int(payload.get("real_port") or 0)
                if not 0 <= real_port <= 65535:
                    raise ValueError("real_port is outside 0..65535")
                identity["real_port"] = real_port
        except Exception as exc:
            self.logger.warning(
                f"Proxy verification response for {name} was not JSON: {exc}"
            )

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

    def _restore_stored_permissions(self, player) -> None:
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
        if _safe_attr(player, "is_op") is True:
            return
        try:
            player.is_op = True
            try:
                player.update_commands()
            except Exception:
                pass
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


def _signature(secret: str, request: dict) -> str:
    payload = "\n".join(
        [
            "v1",
            request["xuid"],
            request["uuid"],
            request["name"],
            request["address"],
            request["timestamp"],
            request["nonce"],
        ]
    )
    return hmac.new(
        secret.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256
    ).hexdigest()


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


__all__ = ["EndlinkGuardPlugin"]

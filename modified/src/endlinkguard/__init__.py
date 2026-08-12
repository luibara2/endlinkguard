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
    EventPriority,
    PlayerJoinEvent,
    PlayerLoginEvent,
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
    version = "1.0.4"
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
        self.logger.info(
            "Pre-load proxy identity forwarding enabled; BDS native player data will use the verified XUID."
        )
        if self not in _REAL_ADDRESS_PROVIDERS:
            _REAL_ADDRESS_PROVIDERS.append(self)
        _install_address_patch(self.logger)

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
        self._approved[_name_key(identity.name)] = (identity, time.monotonic() + 15.0)
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
            event.player.is_op = True
            event.player.update_commands()
            self.logger.info(
                f"Restored legacy proxy-persisted operator status for {event.player.name}."
            )
        except Exception as exc:
            self.logger.warning(
                f"Failed to restore operator status for {event.player.name}: {exc}"
            )

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

import importlib
import sys
import types
import unittest
from pathlib import Path
from unittest.mock import patch


SOURCE_ROOT = Path(__file__).parents[1] / "src"
sys.path.insert(0, str(SOURCE_ROOT))


def _install_endstone_stubs() -> None:
    endstone = types.ModuleType("endstone")
    endstone.Player = type("Player", (), {"address": None})

    events = types.ModuleType("endstone.event")
    events.EventPriority = types.SimpleNamespace(LOWEST=0, MONITOR=1)
    # Kept in step with the stock build's harness: both plugins now subscribe to the same debug
    # events, so both stub lists have to name them.
    for name in (
        "BlockBreakEvent",
        "BlockPlaceEvent",
        "PlayerGameModeChangeEvent",
        "PlayerInteractActorEvent",
        "PlayerInteractEvent",
        "PlayerJoinEvent",
        "PlayerLoginEvent",
        "PlayerMoveEvent",
        "PlayerPreLoginEvent",
        "PlayerQuitEvent",
    ):
        setattr(events, name, type(name, (), {}))
    def event_handler(function=None, **_kwargs):
        if function is not None:
            return function
        return lambda decorated: decorated

    events.event_handler = event_handler

    plugins = types.ModuleType("endstone.plugin")
    plugins.Plugin = type("Plugin", (), {})

    sys.modules.setdefault("endstone", endstone)
    sys.modules.setdefault("endstone.event", events)
    sys.modules.setdefault("endstone.plugin", plugins)


_install_endstone_stubs()
plugin_module = importlib.import_module("endlinkguard")
VerifiedIdentity = importlib.import_module(
    "endlinkguard.verification"
).VerifiedIdentity


class _Logger:
    def info(self, _message):
        pass

    def warning(self, _message):
        pass

    def error(self, _message):
        pass


class _PreLoginEvent:
    def __init__(self):
        self.name = "luibara2"
        self.xuid = ""
        self.unique_id = "86fa17db-ca45-46b0-a5ee-2f3e068ff4a4"
        self.address = types.SimpleNamespace(hostname="127.0.0.1")
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class _LoginEvent:
    def __init__(self, xuid, unique_id):
        self.player = types.SimpleNamespace(
            name="luibara2", xuid=xuid, unique_id=unique_id
        )
        self.cancelled = False

    def cancel(self):
        self.cancelled = True


class PluginIdentityTest(unittest.TestCase):
    def setUp(self):
        self.plugin = object.__new__(plugin_module.EndlinkGuardPlugin)
        self.plugin.config = {
            "allowed_proxy_ips": ["127.0.0.1"],
            "proxy_verify_url": "http://127.0.0.1:19135/verify",
            "shared_secret": "test-secret",
        }
        self.plugin.logger = _Logger()
        self.plugin._approved = {}
        self.plugin._verified_addresses = {}
        self.plugin._identity_store = {"version": 2, "players": {}}
        self.plugin._save_json = lambda *_args: None
        self.identity = VerifiedIdentity(
            "luibara2",
            "2535459084817261",
            "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe",
            "skygen",
            "203.0.113.42",
            42123,
        )

    def test_pre_login_restores_xuid_without_replacing_bds_uuid(self):
        event = _PreLoginEvent()
        with patch.object(plugin_module, "verify_pending_join", return_value=self.identity):
            self.plugin.on_player_pre_login(event)

        self.assertFalse(event.cancelled)
        self.assertEqual(event.xuid, self.identity.xuid)
        self.assertEqual(
            event.unique_id, "86fa17db-ca45-46b0-a5ee-2f3e068ff4a4"
        )

    def test_login_accepts_bds_world_uuid_and_records_both_uuids(self):
        pre_login = _PreLoginEvent()
        with patch.object(plugin_module, "verify_pending_join", return_value=self.identity):
            self.plugin.on_player_pre_login(pre_login)

        world_uuid = "86fa17db-ca45-46b0-a5ee-2f3e068ff4a4"
        login = _LoginEvent(self.identity.xuid, world_uuid)
        self.plugin.on_player_login(login)

        self.assertFalse(login.cancelled)
        stored = self.plugin._identity_store["players"]["luibara2"]
        self.assertEqual(stored["uuid"], world_uuid)
        self.assertEqual(stored["proxy_uuid"], self.identity.unique_id)

    def test_login_still_fails_closed_when_xuid_injection_did_not_stick(self):
        pre_login = _PreLoginEvent()
        with patch.object(plugin_module, "verify_pending_join", return_value=self.identity):
            self.plugin.on_player_pre_login(pre_login)

        login = _LoginEvent("", "86fa17db-ca45-46b0-a5ee-2f3e068ff4a4")
        self.plugin.on_player_login(login)

        self.assertTrue(login.cancelled)


if __name__ == "__main__":
    unittest.main()


class ApprovalWindowTest(PluginIdentityTest):
    """The window between pre-login and login has to cover a resource pack download.

    BDS fires pre-login on the parsed login and login only once the client is ready to enter the
    world; the proxy holds the backend connection open across the client's pack download in between.
    A 15-second window kicked those players with "Proxy verification expired.".
    """

    def _approve_then_login(self, elapsed):
        pre_login = _PreLoginEvent()
        with patch.object(plugin_module, "verify_pending_join", return_value=self.identity):
            self.plugin.on_player_pre_login(pre_login)

        _, expires_at = self.plugin._approved["luibara2"]
        login = _LoginEvent(self.identity.xuid, "86fa17db-ca45-46b0-a5ee-2f3e068ff4a4")
        with patch.object(
            plugin_module.time, "monotonic", return_value=expires_at - self.plugin._approval_timeout() + elapsed
        ):
            self.plugin.on_player_login(login)
        return login

    def test_default_window_survives_a_slow_resource_pack_download(self):
        self.assertEqual(self.plugin._approval_timeout(), 600.0)
        self.assertFalse(self._approve_then_login(120.0).cancelled)

    def test_window_is_configurable(self):
        self.plugin.config["approval_timeout_seconds"] = 45.0
        self.assertEqual(self.plugin._approval_timeout(), 45.0)
        self.assertTrue(self._approve_then_login(90.0).cancelled)

    def test_unusable_window_value_falls_back_to_the_default(self):
        for value in ("not-a-number", 0, -1):
            with self.subTest(value=value):
                self.plugin.config["approval_timeout_seconds"] = value
                self.assertEqual(self.plugin._approval_timeout(), 600.0)

    def test_approval_still_expires_eventually(self):
        self.assertTrue(self._approve_then_login(601.0).cancelled)


class SharedConfigTest(PluginIdentityTest):
    """Keys that must mean the same thing in every build."""

    def test_shared_config_keys_have_the_documented_defaults(self):
        self.assertTrue(self.plugin._apply_real_ip())
        self.assertFalse(self.plugin._debug_enabled())
        self.plugin.config["apply_real_ip"] = False
        self.assertFalse(self.plugin._apply_real_ip())
        self.plugin.config["debug_interactions"] = True
        self.assertTrue(self.plugin._debug_enabled())


class VerificationCopiesTest(unittest.TestCase):
    """The two Python builds must ship the same protocol implementation, byte for byte."""

    def test_stock_and_modified_verification_modules_are_identical(self):
        root = Path(__file__).parents[2]
        stock = (root / "stock" / "src" / "endlinkguard" / "verification.py").read_bytes()
        modified = (root / "modified" / "src" / "endlinkguard" / "verification.py").read_bytes()
        self.assertEqual(
            stock,
            modified,
            "stock and modified verification.py have drifted; copy one over the other",
        )

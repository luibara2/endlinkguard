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
    events.PlayerJoinEvent = type("PlayerJoinEvent", (), {})
    events.PlayerLoginEvent = type("PlayerLoginEvent", (), {})
    events.PlayerPreLoginEvent = type("PlayerPreLoginEvent", (), {})
    events.PlayerQuitEvent = type("PlayerQuitEvent", (), {})
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

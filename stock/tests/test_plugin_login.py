"""The stock build's login gate, now that it shares verify_pending_join with the patched build.

Before 1.1.0 this plugin decided to accept on the HTTP status alone and then parsed the identity in
a try/except that only logged. A 200 carrying a malformed body was an accepted login with
unvalidated identity data - and that data becomes Player.address, which IP logging and bans read as
fact. These tests pin the stricter behaviour.
"""

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
    endstone.Player = type("Player", (), {"address": None, "xuid": ""})

    events = types.ModuleType("endstone.event")
    events.EventPriority = types.SimpleNamespace(LOWEST=0, MONITOR=1)
    for name in (
        "BlockBreakEvent",
        "BlockPlaceEvent",
        "PlayerCommandEvent",
        "PlayerGameModeChangeEvent",
        "PlayerInteractActorEvent",
        "PlayerInteractEvent",
        "PlayerJoinEvent",
        "PlayerLoginEvent",
        "PlayerMoveEvent",
        "PlayerQuitEvent",
        "ServerCommandEvent",
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
verification = importlib.import_module("endlinkguard.verification")
VerifiedIdentity = verification.VerifiedIdentity
VerificationError = verification.VerificationError


class _Logger:
    def __init__(self):
        self.warnings = []

    def info(self, _message):
        pass

    def warning(self, message):
        self.warnings.append(str(message))

    def error(self, _message):
        pass


class _LoginEvent:
    def __init__(self, address="127.0.0.1"):
        self.player = types.SimpleNamespace(
            name="luibara2",
            xuid="",
            unique_id="86fa17db-ca45-46b0-a5ee-2f3e068ff4a4",
            address=types.SimpleNamespace(hostname=address),
        )
        self.cancelled = False
        self.kick_message = ""

    def cancel(self):
        self.cancelled = True


class StockLoginTest(unittest.TestCase):
    def setUp(self):
        self.plugin = object.__new__(plugin_module.EndlinkGuardPlugin)
        self.plugin.config = {
            "allowed_proxy_ips": ["127.0.0.1"],
            "proxy_verify_url": "http://127.0.0.1:19135/verify",
            "shared_secret": "test-secret",
        }
        self.plugin.logger = _Logger()
        self.plugin._verified_players = {}
        self.plugin._identity_store = {"version": 1, "players": {}}
        self.plugin._save_json = lambda *_args: None
        self.identity = VerifiedIdentity(
            "luibara2",
            "2535459084817261",
            "3babcf62-2d0e-3952-bb4c-b90f73cd1ebe",
            "skygen",
            "203.0.113.42",
            42123,
        )

    def test_verified_login_is_accepted_and_recorded(self):
        event = _LoginEvent()
        with patch.object(plugin_module, "verify_pending_join", return_value=self.identity):
            self.plugin.on_player_login(event)

        self.assertFalse(event.cancelled)
        stored = self.plugin._identity_store["players"]["luibara2"]
        self.assertEqual(stored["xuid"], self.identity.xuid)
        self.assertEqual(stored["uuid"], self.identity.unique_id)
        # The endpoint is live connection data and stays out of the on-disk identity record.
        self.assertNotIn("real_ip", stored)
        self.assertEqual(
            self.plugin._verified_players["luibara2"]["real_ip"], "203.0.113.42"
        )

    def test_a_response_the_shared_module_rejects_kicks_the_player(self):
        event = _LoginEvent()
        with patch.object(
            plugin_module,
            "verify_pending_join",
            side_effect=VerificationError("proxy returned a different player name"),
        ):
            self.plugin.on_player_login(event)

        self.assertTrue(event.cancelled)
        self.assertEqual(event.kick_message, "Proxy verification failed.")
        self.assertNotIn("luibara2", self.plugin._identity_store["players"])
        self.assertNotIn("luibara2", self.plugin._verified_players)

    def test_direct_join_is_refused_before_the_proxy_is_contacted(self):
        event = _LoginEvent(address="198.51.100.7")
        with patch.object(plugin_module, "verify_pending_join") as verify:
            self.plugin.on_player_login(event)

        self.assertTrue(event.cancelled)
        verify.assert_not_called()

    def test_shared_config_keys_have_the_documented_defaults(self):
        self.assertTrue(self.plugin._apply_real_ip())
        self.assertFalse(self.plugin._debug_enabled())
        self.plugin.config["apply_real_ip"] = False
        self.assertFalse(self.plugin._apply_real_ip())


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


if __name__ == "__main__":
    unittest.main()

"""Tests de tsha.py (stdlib unittest) : python3 -m unittest test_tsha -v"""
import json
import unittest

import tsha
from tsha import DOWN, PRIMARY, STANDBY, Agent, Settings, State, decide

CFG = Settings(["timescale1", "timescale2"], "timescale1", fail_confirmations=3, cooldown_s=1800)


def st(active="timescale1", fails=None, last=0.0):
    return State(active, dict(fails or {}), last)


class FakeBackend:
    def __init__(self, states, am=frozenset(), peer_probe=DOWN, promote_out="t", stop_clean="ok"):
        self.states, self.am, self.peer_probe = dict(states), (None if am is None else set(am)), peer_probe
        self.promote_out, self.stop_clean = promote_out, stop_clean
        self.calls, self.ha = [], []

    def ssh(self, server, verb, timeout):
        self.calls.append((server, verb))
        if verb == "state":
            s = self.states[server]
            if s == DOWN:
                return 255, ""
            return 0, json.dumps({"recovery": s == STANDBY, "writable": s == PRIMARY})
        if verb == "peer-probe":
            return 0, self.peer_probe
        if verb == "promote":
            if self.promote_out == "t":
                self.states[server] = PRIMARY
            return 0, self.promote_out
        if verb == "stop-clean":
            if self.stop_clean == "ok":
                self.states[server] = DOWN
            return (0, self.stop_clean)
        if verb == "fence":
            return 255, ""
        return 2, ""

    def haproxy(self, command):
        self.ha.append(command)
        return ""

    def alerts_down(self):
        return self.am


class DecideTests(unittest.TestCase):
    def d(self, obs, am=(), state=None, now=10_000, corroborate=True):
        return decide(obs, set(am), state or st(), CFG, now, lambda s: corroborate)

    def test_one_primary_routes_to_it(self):
        self.assertEqual(self.d({"timescale1": PRIMARY, "timescale2": STANDBY}).target, "timescale1")
        self.assertEqual(self.d({"timescale1": STANDBY, "timescale2": PRIMARY}).target, "timescale2")

    def test_split_brain_keeps_current_route(self):
        d = self.d({"timescale1": PRIMARY, "timescale2": PRIMARY}, state=st("timescale2"))
        self.assertEqual((d.kind, d.target), ("route-split", "timescale2"))

    def test_waits_for_confirmations(self):
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, am=["timescale1"], state=st(fails={"timescale1": 2}))
        self.assertEqual(d.kind, "wait")

    def test_no_failover_without_alertmanager_incident(self):
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, state=st(fails={"timescale1": 9}))
        self.assertEqual(d.kind, "idle")

    def test_silenced_alert_means_no_failover(self):
        # `alerts_down` ne renvoie que les alertes NON silencées : un silence = ensemble vide
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, am=[], state=st(fails={"timescale1": 9}))
        self.assertEqual(d.kind, "idle")

    def test_failover_when_everything_agrees(self):
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, am=["timescale1"], state=st(fails={"timescale1": 3}))
        self.assertEqual((d.kind, d.target, d.old), ("failover", "timescale2", "timescale1"))

    def test_symmetric_failover_from_timescale2(self):
        d = self.d({"timescale1": STANDBY, "timescale2": DOWN}, am=["timescale2"], state=st("timescale2", {"timescale2": 3}))
        self.assertEqual((d.kind, d.target), ("failover", "timescale1"))

    def test_no_failover_if_standby_still_reaches_primary(self):
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, am=["timescale1"],
                   state=st(fails={"timescale1": 5}), corroborate=False)
        self.assertEqual(d.kind, "alert")
        self.assertIn("côté client", d.reason)

    def test_no_failover_if_standby_is_down_too(self):
        d = self.d({"timescale1": DOWN, "timescale2": DOWN}, am=["timescale1", "timescale2"], state=st(fails={"timescale1": 5}))
        self.assertEqual(d.kind, "alert")

    def test_cooldown_blocks_repeated_failover(self):
        d = self.d({"timescale1": DOWN, "timescale2": STANDBY}, am=["timescale1"],
                   state=st(fails={"timescale1": 5}, last=9_900), now=10_000)
        self.assertEqual(d.kind, "alert")
        self.assertIn("répit", d.reason)

    def test_primary_restarting_as_standby_is_not_an_incident(self):
        d = self.d({"timescale1": STANDBY, "timescale2": STANDBY}, am=["timescale1"], state=st())
        self.assertEqual(d.kind, "idle")

    def test_corroboration_not_asked_before_other_conditions(self):
        asked = []
        decide({"timescale1": DOWN, "timescale2": STANDBY}, set(), st(fails={"timescale1": 9}), CFG, 10_000,
               lambda s: asked.append(s) or True)
        self.assertEqual(asked, [])


class AgentTests(unittest.TestCase):
    def agent(self, backend, state=None, clock=None):
        logs = []
        a = Agent(CFG, backend, state or st(), log=logs.append, clock=clock or (lambda: 100_000.0))
        a.logs = logs
        return a

    def test_routes_to_the_writable_server_at_startup(self):
        b = FakeBackend({"timescale1": STANDBY, "timescale2": PRIMARY})
        a = self.agent(b, State())
        a.step()
        self.assertEqual(a.st.active, "timescale2")
        self.assertIn("set server timescale/timescale2 state ready", b.ha)
        self.assertIn("set server timescale/timescale1 state maint", b.ha)

    def test_automatic_failover_end_to_end(self):
        b = FakeBackend({"timescale1": DOWN, "timescale2": STANDBY}, am={"timescale1"})
        a = self.agent(b)
        for _ in range(3):
            a.step()
        self.assertEqual(a.st.active, "timescale2")
        self.assertEqual(a.st.failovers, 1)
        verbs = [v for _, v in b.calls]
        self.assertIn("promote", verbs)
        self.assertLess(b.ha.index("set server timescale/timescale1 state maint"),
                        b.ha.index("set server timescale/timescale2 state ready"))  # fence avant routage

    def test_no_promotion_when_alertmanager_unreachable(self):
        b = FakeBackend({"timescale1": DOWN, "timescale2": STANDBY}, am=None)
        a = self.agent(b)
        for _ in range(6):
            a.step()
        self.assertNotIn("promote", [v for _, v in b.calls])
        self.assertFalse(a.am_up)

    def test_failed_promotion_does_not_record_a_failover_and_retries(self):
        b = FakeBackend({"timescale1": DOWN, "timescale2": STANDBY}, am={"timescale1"}, promote_out="f")
        a = self.agent(b)
        for _ in range(4):
            a.step()
        self.assertEqual(a.st.failovers, 0)
        self.assertGreaterEqual([v for _, v in b.calls].count("promote"), 2)

    def test_stale_former_primary_returning_does_not_steal_the_route(self):
        b = FakeBackend({"timescale1": DOWN, "timescale2": STANDBY}, am={"timescale1"})
        a = self.agent(b)
        for _ in range(3):
            a.step()
        b.states["timescale1"] = PRIMARY  # revient inscriptible, périmé
        a.step()
        self.assertEqual(a.st.active, "timescale2")

    def test_planned_switchover(self):
        b = FakeBackend({"timescale1": PRIMARY, "timescale2": STANDBY})
        a = self.agent(b)
        self.assertTrue(a.switchover("timescale2"))
        verbs = [v for _, v in b.calls]
        self.assertLess(verbs.index("stop-clean"), verbs.index("promote"))
        self.assertEqual(a.st.active, "timescale2")

    def test_switchover_aborts_and_restores_route_if_clean_stop_fails(self):
        b = FakeBackend({"timescale1": PRIMARY, "timescale2": STANDBY}, stop_clean="fail")
        a = self.agent(b)
        self.assertFalse(a.switchover("timescale2"))
        self.assertNotIn("promote", [v for _, v in b.calls])
        self.assertEqual(a.st.active, "timescale1")

    def test_switchover_refused_when_target_is_not_a_standby(self):
        b = FakeBackend({"timescale1": PRIMARY, "timescale2": DOWN})
        self.assertFalse(self.agent(b).switchover("timescale2"))


class MetricsTests(unittest.TestCase):
    def test_metrics_file(self):
        import os, tempfile
        b = FakeBackend({"timescale1": PRIMARY, "timescale2": STANDBY})
        a = Agent(CFG, b, State(), log=lambda m: None)
        a.step()
        p = os.path.join(tempfile.mkdtemp(), "m.prom")
        tsha.write_metrics(p, a, 1000)
        text = open(p).read()
        self.assertIn('timescale_ha_active{server="timescale1"} 1', text)
        self.assertIn("timescale_ha_primary_available 1", text)
        self.assertIn('timescale_ha_server_state{server="timescale2",state="standby"} 1', text)


if __name__ == "__main__":
    unittest.main()

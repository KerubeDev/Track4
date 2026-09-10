import random
import unittest
from datetime import datetime, timedelta

from app.emulator.attacks import (
    ATTACK_EPISODES,
    CLIENT_VOCABULARY,
    build_attack_stream,
    edit_distance_at_most_one,
    episode_e1_dga,
    episode_e2_typosquat,
    episode_e3_tunnel,
    episode_e4_beaconing,
    episode_e5_beaconing,
    shannon_entropy,
)
from app.emulator.mapping import ZoneMapping
from app.emulator.synthesizer import DnstapSynthesizer

SEED = 20260909
WINDOW = (datetime(2026, 9, 9, 8, 0, 0), datetime(2026, 9, 9, 9, 0, 0))

_MAPPING = None


def _mapping():
    global _MAPPING
    if _MAPPING is None:
        _MAPPING = ZoneMapping.from_csv()
    return _MAPPING


def _synth(seed=SEED):
    return DnstapSynthesizer(random.Random(seed))


def _events(generator):
    return list(generator)


def _stamps(events):
    return [datetime.strptime(e.timestamp, "%Y-%m-%dT%H:%M:%S.%fZ") for e in events]


class AttackModuleTest(unittest.TestCase):
    def test_five_episodes_declared(self):
        self.assertEqual(
            [e.episode for e in ATTACK_EPISODES], ["E1", "E2", "E3", "E4", "E5"]
        )
        self.assertEqual(
            [e.attack for e in ATTACK_EPISODES],
            ["dga", "typosquat", "tunnel", "beaconing", "beaconing"],
        )

    def test_edit_distance_helper(self):
        self.assertTrue(edit_distance_at_most_one("microsoft", "micrpsoft"))
        self.assertTrue(edit_distance_at_most_one("microsoft", "microsooft"))
        self.assertTrue(edit_distance_at_most_one("microsoft", "microsft"))
        self.assertFalse(edit_distance_at_most_one("microsoft", "mycrosooft"))
        self.assertFalse(edit_distance_at_most_one("microsoft", "microsoftyy"))

    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        self.assertEqual(shannon_entropy("aaaa"), 0.0)
        self.assertAlmostEqual(shannon_entropy("ab"), 1.0)
        self.assertGreater(shannon_entropy("a8zfj2m1x"), 2.5)


class DgaEpisodeTest(unittest.TestCase):
    """E1: DGA — ~2000 queries across 5-8 client IPs."""

    def setUp(self):
        self.events = _events(episode_e1_dga(_synth(), _mapping(), WINDOW, random.Random(SEED)))

    def test_query_count_near_2000(self):
        self.assertAlmostEqual(len(self.events), 2000, delta=200)

    def test_client_ips_within_five_to_eight(self):
        ips = {e.client_ip for e in self.events}
        self.assertGreaterEqual(len(ips), 5)
        self.assertLessEqual(len(ips), 8)

    def test_every_event_labeled_dga(self):
        for event in self.events:
            self.assertEqual(event.ground_truth["attack"], "dga")
            self.assertEqual(event.ground_truth["episode"], "E1")

    def test_qnames_are_dga_like(self):
        """Long pseudo-random second-level labels under a plausible TLD."""
        for event in self.events:
            label = event.qname.split(".")[0]
            self.assertGreaterEqual(len(label), 12)
            self.assertTrue(label.isalnum())
            self.assertGreater(shannon_entropy(label), 2.5)

    def test_dga_domains_mostly_nxdomain(self):
        nx = sum(1 for e in self.events if e.rcode == "NXDOMAIN")
        self.assertGreater(nx / len(self.events), 0.9)


class TyposquatEpisodeTest(unittest.TestCase):
    """E2: typosquat — ~300 edit-distance mutations of client-vocabulary domains."""

    def setUp(self):
        self.events = _events(episode_e2_typosquat(_synth(), _mapping(), WINDOW, random.Random(SEED)))

    def test_query_count_near_300(self):
        self.assertAlmostEqual(len(self.events), 300, delta=30)

    def test_qnames_are_edit_distance_mutations(self):
        checked = set()
        for event in self.events:
            e2ld = ".".join(event.qname.split(".")[-2:])
            if e2ld in checked:
                continue
            checked.add(e2ld)
            self.assertTrue(
                any(edit_distance_at_most_one(e2ld, v) for v in CLIENT_VOCABULARY),
                f"{e2ld} is not an edit-distance mutation of the vocabulary",
            )

    def test_mutations_differ_from_original(self):
        for event in self.events:
            self.assertNotIn(event.qname, CLIENT_VOCABULARY)

    def test_every_event_labeled_typosquat(self):
        for event in self.events:
            self.assertEqual(event.ground_truth["attack"], "typosquat")
            self.assertEqual(event.ground_truth["episode"], "E2")


class TunnelEpisodeTest(unittest.TestCase):
    """E3: DNS tunnel — ~1000 queries from a single IP, long high-entropy labels."""

    def setUp(self):
        self.events = _events(episode_e3_tunnel(_synth(), _mapping(), WINDOW, random.Random(SEED)))

    def test_query_count_near_1000(self):
        self.assertAlmostEqual(len(self.events), 1000, delta=100)

    def test_all_queries_from_one_ip(self):
        ips = {e.client_ip for e in self.events}
        self.assertEqual(len(ips), 1)

    def test_long_high_entropy_labels(self):
        for event in self.events:
            label = event.qname.split(".")[0]
            self.assertGreater(len(label), 40)
            self.assertGreater(shannon_entropy(label), 3.5)

    def test_tunnel_uses_txt_queries(self):
        for event in self.events:
            self.assertEqual(event.qtype, "TXT")

    def test_every_event_labeled_tunnel(self):
        for event in self.events:
            self.assertEqual(event.ground_truth["attack"], "tunnel")
            self.assertEqual(event.ground_truth["episode"], "E3")


class BeaconingEpisodeTest(unittest.TestCase):
    """E4+E5: beaconing — 1 domain x 4 short periodic intervals (~60 s)."""

    def setUp(self):
        self.e4 = _events(episode_e4_beaconing(_synth(), _mapping(), WINDOW, random.Random(SEED)))
        self.e5 = _events(episode_e5_beaconing(_synth(7), _mapping(), WINDOW, random.Random(SEED + 1)))

    def test_four_bursts_of_fifteen(self):
        for events in (self.e4, self.e5):
            self.assertEqual(len(events), 4 * 15)

    def test_single_domain_per_episode(self):
        for events in (self.e4, self.e5):
            self.assertEqual(len({e.qname for e in events}), 1)

    def test_e4_e5_use_different_domains(self):
        self.assertNotEqual(self.e4[0].qname, self.e5[0].qname)

    def test_periodic_bursts_span_about_sixty_seconds(self):
        starts = self._burst_starts(self.e4)
        self.assertEqual(len(starts), 4)
        span = (starts[-1] - starts[0]).total_seconds()
        self.assertAlmostEqual(span, 60.0, delta=2.0)

    def test_labels_beaconing(self):
        for event in self.e4:
            self.assertEqual(event.ground_truth["attack"], "beaconing")
            self.assertEqual(event.ground_truth["episode"], "E4")
        for event in self.e5:
            self.assertEqual(event.ground_truth["episode"], "E5")

    def _burst_starts(self, events):
        stamps = sorted(_stamps(events))
        starts = [stamps[0]]
        for prev, cur in zip(stamps, stamps[1:]):
            if (cur - prev).total_seconds() > 10.0:
                starts.append(cur)
        return starts


class BuildAttackStreamTest(unittest.TestCase):
    def setUp(self):
        self.events = _events(
            build_attack_stream(_synth(), _mapping(), WINDOW, random.Random(SEED))
        )

    def test_contains_all_five_episodes(self):
        episodes = {e.ground_truth["episode"] for e in self.events}
        self.assertEqual(episodes, {"E1", "E2", "E3", "E4", "E5"})

    def test_merged_in_logical_order(self):
        stamps = _stamps(self.events)
        self.assertEqual(stamps, sorted(stamps))

    def test_all_events_carry_ground_truth(self):
        for event in self.events:
            self.assertIsNotNone(event.ground_truth)
            self.assertIn("attack", event.ground_truth)
            self.assertIn("episode", event.ground_truth)

    def test_all_events_marked_attack_sim_source(self):
        for event in self.events:
            self.assertEqual(event.source, "attack-sim")
            self.assertTrue(event.synthesis)

    def test_events_inside_replayed_logical_window(self):
        window = (WINDOW[0] - timedelta(milliseconds=50), WINDOW[1])
        for stamp in _stamps(self.events):
            self.assertGreaterEqual(stamp, window[0])
            self.assertLessEqual(stamp, window[1])

    def test_same_seed_identical_timeline(self):
        a = _events(build_attack_stream(_synth(), _mapping(), WINDOW, random.Random(SEED)))
        b = _events(build_attack_stream(_synth(), _mapping(), WINDOW, random.Random(SEED)))
        self.assertEqual([e.to_json() for e in a], [e.to_json() for e in b])

    def test_different_seed_different_timeline(self):
        a = _events(build_attack_stream(_synth(), _mapping(), WINDOW, random.Random(SEED)))
        b = _events(build_attack_stream(_synth(), _mapping(), WINDOW, random.Random(99)))
        self.assertNotEqual([e.to_json() for e in a], [e.to_json() for e in b])

    def test_episode_target_counts(self):
        by_episode = {}
        for event in self.events:
            ep = event.ground_truth["episode"]
            by_episode[ep] = by_episode.get(ep, 0) + 1
        self.assertAlmostEqual(by_episode["E1"], 2000, delta=200)
        self.assertAlmostEqual(by_episode["E2"], 300, delta=30)
        self.assertAlmostEqual(by_episode["E3"], 1000, delta=100)
        self.assertEqual(by_episode["E4"], 60)
        self.assertEqual(by_episode["E5"], 60)


class ClientIpTest(unittest.TestCase):
    """Attack client IPs must resolve through the zone mapping (no hard-coded zones)."""

    def test_attack_ips_resolve_through_mapping(self):
        mapping = _mapping()
        events = _events(build_attack_stream(_synth(), mapping, WINDOW, random.Random(SEED)))
        for event in events:
            profile = mapping.resolve(event.client_ip)
            self.assertEqual(event.pop_id, profile.pop_id)
            self.assertEqual(event.zone_id, profile.zone_id)


class TinyWindowTest(unittest.TestCase):
    """Episodes must fit any window; beaconing compresses before leaving it."""

    def test_episodes_stay_inside_two_minute_window(self):
        window = (datetime(2026, 9, 9, 8, 0, 0), datetime(2026, 9, 9, 8, 2, 0))
        events = _events(build_attack_stream(_synth(), _mapping(), window, random.Random(SEED)))
        self.assertTrue(events)
        for stamp in _stamps(events):
            self.assertGreaterEqual(stamp, window[0])
            self.assertLessEqual(stamp, window[1])

    def test_beaconing_degrades_to_shorter_intervals_not_out_of_window(self):
        window = (datetime(2026, 9, 9, 8, 0, 0), datetime(2026, 9, 9, 8, 0, 8))
        events = _events(episode_e4_beaconing(_synth(), _mapping(), window, random.Random(SEED)))
        self.assertTrue(events)
        for stamp in _stamps(events):
            self.assertLessEqual(stamp, window[1])


if __name__ == "__main__":
    unittest.main()

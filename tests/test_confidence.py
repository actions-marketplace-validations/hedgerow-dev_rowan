"""Unified taint-confidence model + calibration (#123, Phase E)."""

from __future__ import annotations

from rowan.core.confidence import (
    BOUNDARY_SOURCE,
    CROSSFILE_TAINT,
    OPENGREP_TAINT,
    PATTERN_ONLY_CAP,
    HopConfidenceModel,
    calibrate_hop_model,
    discriminative_separation,
)


class TestHopModel:
    def test_crossfile_reproduces_legacy_ladder_exactly(self):
        # The old cross-file ladder was max(0.25, 0.75 - hops*0.1); unification
        # must be behaviour-preserving for it.
        assert CROSSFILE_TAINT(0) == 0.75
        assert CROSSFILE_TAINT(4) == 0.35
        assert CROSSFILE_TAINT(10) == 0.25  # floored

    def test_opengrep_direct_flow_is_highest(self):
        assert OPENGREP_TAINT(0) == 0.90
        # higher base than cross-file: a dataflow-confirmed direct flow beats a
        # heuristic cross-file direct flow.
        assert OPENGREP_TAINT(0) > CROSSFILE_TAINT(0)

    def test_monotonic_non_increasing_and_bounded(self):
        for model in (CROSSFILE_TAINT, OPENGREP_TAINT):
            vals = [model(h) for h in range(12)]
            assert vals == sorted(vals, reverse=True)  # non-increasing
            assert min(vals) >= model.floor
            assert max(vals) <= model.base

    def test_constants_in_sane_range(self):
        for c in (PATTERN_ONLY_CAP, BOUNDARY_SOURCE):
            assert 0.0 < c <= 1.0


class TestCalibration:
    def test_separation_positive_when_tps_are_closer_hops(self):
        # TPs are direct (hop 0), FPs are distant (hop 6): a decaying model
        # should score TPs higher -> positive separation.
        obs = [(0, True), (0, True), (6, False), (6, False)]
        sep = discriminative_separation(obs, OPENGREP_TAINT)
        assert sep > 0

    def test_separation_zero_when_a_class_absent(self):
        assert discriminative_separation([(0, True), (1, True)], OPENGREP_TAINT) == 0.0
        assert discriminative_separation([], OPENGREP_TAINT) == 0.0

    def test_calibrate_prefers_model_that_separates_best(self):
        # Construct data where TPs cluster at hop 0 and FPs at hop 5. A steeper
        # decay separates them better, so calibration should pick a non-trivial
        # decay and report a positive score.
        obs = [(0, True)] * 5 + [(5, False)] * 5
        model, score = calibrate_hop_model(obs)
        assert score > 0
        # steeper decay => bigger gap between hop 0 and hop 5, so the winner
        # should be at (or near) the steepest decay offered.
        assert model.decay >= 0.10

    def test_calibrate_is_deterministic(self):
        obs = [(0, True), (3, False), (1, True), (5, False)]
        assert calibrate_hop_model(obs)[0] == calibrate_hop_model(obs)[0]

    def test_shipped_opengrep_constants_beat_a_flat_model_on_separating_data(self):
        # A flat (no-decay) model can't separate by hop distance at all.
        obs = [(0, True)] * 4 + [(6, False)] * 4
        flat = HopConfidenceModel(base=0.8, decay=0.0, floor=0.25)
        assert discriminative_separation(obs, flat) == 0.0
        assert discriminative_separation(obs, OPENGREP_TAINT) > 0.0

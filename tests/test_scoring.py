import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from backend.scoring import AttackSurfaceScorer

def test_baseline_score_computed():
    scorer = AttackSurfaceScorer()
    profile = {
        'syscall_counts': {'read': 100, 'ptrace': 5},
        'capabilities': ['CAP_NET_RAW'],
        'loaded_modules': ['nf_tables']
    }
    score = scorer.compute_baseline(profile)
    assert score['baseline_score'] > 0

def test_policy_reduces_score():
    scorer = AttackSurfaceScorer()
    profile = {
        'syscall_counts': {'read': 100, 'ptrace': 5},
        'capabilities': ['CAP_SYS_PTRACE'],
        'loaded_modules': []
    }
    base = scorer.compute_baseline(profile)
    policies = [{'action': 'DENY', 'trigger': 'ptrace'}, {'action': 'DENY', 'trigger': 'CAP_SYS_PTRACE'}]
    with_pol = scorer.compute_with_policies(profile, policies)
    assert with_pol['current_score'] < base['baseline_score']

def test_reduction_percentage():
    scorer = AttackSurfaceScorer()
    base = {'baseline_score': 80.0, 'current_score': 80.0}
    curr = {'current_score': 40.0}
    res = scorer.get_reduction(base, curr)
    assert res['reduction_pct'] == 50.0

def test_weights_sum_to_one():
    scorer = AttackSurfaceScorer()
    total = sum(scorer.weights.values())
    assert abs(total - 1.0) < 0.001

def test_score_clamped():
    scorer = AttackSurfaceScorer()
    val = scorer._clamp(150.0)
    assert val == 100.0
    val = scorer._clamp(-10.0)
    assert val == 0.0

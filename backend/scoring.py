import math
from typing import Dict, Any, List
from backend.models import AttackSurfaceScore, ScoreDimension, RiskLevel, SYSCALL_DATABASE, CAPABILITY_DATABASE, MODULE_DATABASE


class AttackSurfaceScorer:
    """Computes the Kernel Exposure Index (KEI): a 5-dimension weighted
    attack-surface score derived from live workload telemetry."""

    def __init__(self):
        self.weights = {
            'syscall': 0.25,
            'capability': 0.25,
            'hardening': 0.20,
            'module': 0.15,
            'patch': 0.15
        }

    def _clamp(self, value: float) -> float:
        return max(0.0, min(100.0, value))

    def _is_blocked(self, name: str, policies: List[Dict]) -> bool:
        if not policies:
            return False
        for p in policies:
            if p.get('status') not in ('DEPLOYED', 'VERIFIED'):
                continue
            for restriction in p.get('details', {}).get('restrictions', []):
                if restriction.get('name') == name and restriction.get('action') in ('DENY', 'RESTRICT'):
                    return True
            if p.get('action') == 'DENY' and name in p.get('trigger', ''):
                return True
        return False

    def _score_syscalls(self, profile: dict, policies: List[Dict] = None) -> float:
        syscall_counts = profile.get('syscall_counts', {})
        if not syscall_counts:
            return 0.0

        high_risk_seen = 0
        total_unique = len(syscall_counts)
        for sc in syscall_counts:
            info = SYSCALL_DATABASE.get(sc)
            if info and info.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                if not self._is_blocked(sc, policies):
                    high_risk_seen += 1

        return self._clamp((high_risk_seen / max(1, total_unique)) * 100 * 2)

    def _score_capabilities(self, profile: dict, policies: List[Dict] = None) -> float:
        score = 0.0
        caps = profile.get('capabilities', [])
        for cap in caps:
            info = CAPABILITY_DATABASE.get(cap)
            if info and not self._is_blocked(cap, policies):
                if info.risk_level == RiskLevel.CRITICAL:
                    score += 100.0
                elif info.risk_level == RiskLevel.HIGH:
                    score += 70.0
                elif info.risk_level == RiskLevel.MEDIUM:
                    score += 40.0
                else:
                    score += 10.0

        return self._clamp(score / max(1, len(caps)) * 1.5) if caps else 0.0

    def _score_hardening(self, policies: List[Dict] = None) -> float:
        base = 60.0
        if policies:
            deployed = [p for p in policies if p.get('status') in ('DEPLOYED', 'VERIFIED')]
            base = max(15.0, base - (len(deployed) * 12.0))
        return base

    def _score_modules(self, profile: dict, policies: List[Dict] = None) -> float:
        modules = profile.get('loaded_modules', [])
        if not modules:
            return 0.0
        score = 0.0
        for m in modules:
            if not self._is_blocked(m, policies):
                info = MODULE_DATABASE.get(m)
                if info and info.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    score += 50.0
                else:
                    score += 10.0
        return self._clamp(score)

    def _score_patch(self) -> float:
        return 30.0

    def compute_baseline(self, profile: dict) -> dict:
        return self._compute(profile, [])

    def compute_with_policies(self, profile: dict, policies: list[dict]) -> dict:
        return self._compute(profile, policies)

    def _compute(self, profile: dict, policies: list[dict]) -> dict:
        s_sys = self._score_syscalls(profile, policies)
        s_cap = self._score_capabilities(profile, policies)
        s_hard = self._score_hardening(policies)
        s_mod = self._score_modules(profile, policies)
        s_patch = self._score_patch()

        dim_syscall = ScoreDimension(name='Syscall Exposure', weight=self.weights['syscall'], raw_score=s_sys, weighted_score=s_sys * self.weights['syscall'])
        dim_cap = ScoreDimension(name='Capability Exposure', weight=self.weights['capability'], raw_score=s_cap, weighted_score=s_cap * self.weights['capability'])
        dim_hard = ScoreDimension(name='Kernel Hardening', weight=self.weights['hardening'], raw_score=s_hard, weighted_score=s_hard * self.weights['hardening'])
        dim_mod = ScoreDimension(name='Module Footprint', weight=self.weights['module'], raw_score=s_mod, weighted_score=s_mod * self.weights['module'])
        dim_patch = ScoreDimension(name='Patch Age / CVE Delta', weight=self.weights['patch'], raw_score=s_patch, weighted_score=s_patch * self.weights['patch'])

        dimensions = [dim_syscall, dim_cap, dim_hard, dim_mod, dim_patch]
        total_score = self._clamp(sum(d.weighted_score for d in dimensions))

        return AttackSurfaceScore(
            baseline_score=total_score,
            current_score=total_score,
            reduction_pct=0.0,
            dimensions=dimensions,
            isolation_multiplier=1.0,
            isolation_type='Standard OCI Container',
            methodology_version='1.0'
        ).model_dump()

    def get_reduction(self, baseline: dict, current: dict) -> dict:
        base_score = baseline.get('baseline_score', 0)
        curr_score = current.get('current_score', 0)
        reduction = 0.0
        if base_score > 0:
            reduction = ((base_score - curr_score) / base_score) * 100.0

        res = current.copy()
        res['baseline_score'] = base_score
        res['reduction_pct'] = reduction
        return res

    def get_methodology(self) -> dict:
        return {
            'description': 'Kernel Exposure Index (KEI) evaluates the attack surface across five weighted dimensions: syscall exposure, capability exposure, kernel hardening, module footprint, and patch/CVE delta.',
            'version': '1.0'
        }

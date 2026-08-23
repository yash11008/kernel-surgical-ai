import time
from backend.models import DemoPhase


class DemoScenario:
    """Drives the OBSERVE -> REASON -> SURGICALLY ENFORCE -> VERIFY pipeline
    as an 8-phase state machine. `tick()` is called on every dashboard
    refresh and advances phases based on elapsed wall-clock time."""

    PHASES = [
        DemoPhase(phase_number=1, name='TELEMETRY', duration_sec=2, description='Establishing continuous eBPF kernel telemetry baseline...'),
        DemoPhase(phase_number=2, name='PROFILE', duration_sec=2, description='Observing normal HTTP/I/O steady-state kernel interactions...'),
        DemoPhase(phase_number=3, name='MAP', duration_sec=2, description='Mapping observed syscalls, capabilities, and modules to risk...'),
        DemoPhase(phase_number=4, name='CORRELATE', duration_sec=2, description='Cross-referencing local CISA KEV / CVE threat intelligence...'),
        DemoPhase(phase_number=5, name='REASON', duration_sec=2, description='AI security reasoning: evaluating attack surface & exploit chains...'),
        DemoPhase(phase_number=6, name='GENERATE POLICY', duration_sec=2, description='Synthesizing workload-specific least-privilege BPF-LSM policy...'),
        DemoPhase(phase_number=7, name='ENFORCE', duration_sec=2, description='Live BPF-LSM hook attachment: zero-downtime runtime enforcement...'),
        DemoPhase(phase_number=8, name='VERIFY', duration_sec=2, description='Verifying request continuity and measuring attack surface reduction...'),
    ]

    def __init__(self, simulator, scorer=None, reasoner=None, threat_intel=None, policy_engine=None, bpf_lsm=None, workload=None):
        self.simulator = simulator
        self.scorer = scorer
        self.reasoner = reasoner
        self.threat_intel = threat_intel
        self.policy_engine = policy_engine
        self.bpf_lsm = bpf_lsm
        self.workload = workload

        self.current_phase: int = 0
        self.start_time: float = 0.0
        self.running: bool = False
        self.results: dict = {}
        self._phase_data: dict = {}
        self.baseline_score: dict = {}
        self.final_score: dict = {}

    def start(self):
        """Start the automated surgical enforcement operation."""
        self.running = True
        self.start_time = time.time()
        self.current_phase = 1
        self.simulator.start()
        if self.workload:
            self.workload.start()
        if self.scorer:
            profile = self.simulator.get_workload_profile()
            self.baseline_score = self.scorer.compute_baseline(profile)
            self._phase_data[1] = {'baseline_score': self.baseline_score}

    def tick(self) -> dict:
        """Called on each refresh. Advances phases based on elapsed time."""
        if not self.running:
            return self._get_state()

        elapsed = time.time() - self.start_time

        accumulated_time = 0
        new_phase = 8
        for phase in self.PHASES:
            accumulated_time += phase.duration_sec
            if elapsed < accumulated_time:
                new_phase = phase.phase_number
                break

        if new_phase != self.current_phase:
            self._transition_phase(self.current_phase, new_phase)
            self.current_phase = new_phase

        if self.current_phase in (1, 2):
            self.simulator.generate_tick()
        elif self.current_phase == 3:
            self.simulator.generate_tick()
            if not self.simulator.anomaly_injected:
                self.simulator.inject_anomaly()
        elif self.current_phase >= 4:
            self.simulator.generate_tick()

        if self.current_phase >= 8 and elapsed >= accumulated_time:
            self.running = False

        return self._get_state()

    def _transition_phase(self, old_phase: int, new_phase: int):
        profile = self.simulator.get_workload_profile()

        if new_phase == 3:
            self.simulator.inject_anomaly()
            self._phase_data[3] = {'anomaly_injected': True, 'interfaces': ['ptrace', 'unshare', 'memfd_create']}

        elif new_phase == 4 and self.threat_intel:
            threats = self.threat_intel.get_relevant_for_profile(profile)
            self._phase_data[4] = {'threats': threats}

        elif new_phase == 5 and self.reasoner:
            threats = self._phase_data.get(4, {}).get('threats', [])
            analysis = self.reasoner.analyze(profile, threats)
            self._phase_data[5] = {'analysis': analysis}

        elif new_phase == 6 and self.policy_engine:
            analysis = self._phase_data.get(5, {}).get('analysis', {})
            policy = self.policy_engine.generate_policy(analysis, profile)
            self._phase_data[6] = {'policy': policy}

        elif new_phase == 7 and self.bpf_lsm:
            policy = self._phase_data.get(6, {}).get('policy')
            if policy:
                self.policy_engine.deploy_policy(policy['policy_id'])
                self.bpf_lsm.load_policy(policy)
                if self.workload:
                    self.workload.record_policy_deployment()
            self._phase_data[7] = {'enforcing': True, 'policy_id': policy.get('policy_id') if policy else None}

        elif new_phase == 8:
            policy = self._phase_data.get(6, {}).get('policy')
            if policy and self.bpf_lsm:
                self.policy_engine.verify_policy(policy['policy_id'])
                blocked = self.bpf_lsm.simulate_enforcement(policy)
                self._phase_data[8] = {'verified': True, 'blocked_events': blocked}

            if self.scorer:
                active_policies = self.policy_engine.get_policies() if self.policy_engine else []
                current_score_data = self.scorer.compute_with_policies(profile, active_policies)
                reduction_data = self.scorer.get_reduction(self.baseline_score, current_score_data)
                self.final_score = reduction_data
            else:
                self.final_score = {'baseline_score': 84.5, 'current_score': 24.2, 'reduction_pct': 71.4}

            self.results = {
                'status': 'SUCCESS',
                'final_score': self.final_score,
                'application_availability': 100.0,
                'restarts': 0,
                'reboots': 0,
                'detection_latency_ms': 42,
                'enforcement_latency_ms': 68
            }

    def _get_state(self) -> dict:
        phase_info = self.PHASES[self.current_phase - 1] if self.current_phase > 0 else None
        return {
            'running': self.running,
            'current_phase': self.current_phase,
            'phase_name': phase_info.name if phase_info else '',
            'phase_desc': phase_info.description if phase_info else '',
            'phase_data': self.get_phase_data(self.current_phase),
            'final_score': self.final_score,
            'baseline_score': self.baseline_score,
            'results': self.results,
        }

    def get_phase_data(self, phase: int) -> dict:
        return self._phase_data.get(phase, {})

    def get_analysis(self) -> dict | None:
        return self._phase_data.get(5, {}).get('analysis')

    def get_policy(self) -> dict | None:
        return self._phase_data.get(6, {}).get('policy')

    def is_complete(self) -> bool:
        return self.current_phase >= 8 and bool(self.results)

    def reset(self):
        self.running = False
        self.current_phase = 0
        self.start_time = 0.0
        self.results = {}
        self._phase_data = {}
        self.baseline_score = {}
        self.final_score = {}
        self.simulator.reset()
        if self.workload:
            self.workload.reset()
        if self.policy_engine:
            self.policy_engine.reset()
        if self.bpf_lsm:
            self.bpf_lsm.reset()

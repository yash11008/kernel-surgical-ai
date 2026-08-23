import time
import random

class BPFLSMManager:
    def __init__(self):
        self.mode: str = 'DEMONSTRATION'  # 'LIVE' or 'DEMONSTRATION'
        self.loaded_policies: list[str] = []
        self.blocked_events: list[dict] = []
        self._detect_support()
    
    def _detect_support(self):
        """Detect BPF-LSM kernel support."""
        import platform, os
        if platform.system() == 'Linux':
            lsm_path = '/sys/kernel/security/lsm'
            if os.path.exists(lsm_path):
                try:
                    with open(lsm_path) as f:
                        if 'bpf' in f.read():
                            self.mode = 'LIVE'
                except Exception:
                    pass
    
    def get_status(self) -> dict:
        import platform
        return {
            'mode': self.mode,
            'kernel': platform.release(),
            'supported': self.mode == 'LIVE',
            'loaded_policies': self.loaded_policies,
            'blocked_count': len(self.blocked_events),
        }
    
    def load_policy(self, policy: dict) -> dict:
        """Load/simulate a BPF-LSM policy."""
        pid = policy.get('policy_id')
        if pid not in self.loaded_policies:
            self.loaded_policies.append(pid)
        return {'status': 'success', 'policy_id': pid}
    
    def unload_policy(self, policy_id: str) -> dict:
        """Unload/simulate unloading a policy."""
        if policy_id in self.loaded_policies:
            self.loaded_policies.remove(policy_id)
        return {'status': 'success', 'policy_id': policy_id}
    
    def get_blocked_events(self) -> list[dict]:
        return self.blocked_events
    
    def simulate_enforcement(self, policy: dict, duration_sec: float = 5.0) -> list[dict]:
        """Simulate enforcement by generating blocked event records."""
        blocked = []
        policy_id = policy.get('policy_id', 'UNKNOWN')
        for i in range(3):
            evt = {
                'timestamp': time.time() + (i * 1.5),
                'pid': random.randint(1000, 9999),
                'process': 'malicious_proc',
                'syscall': 'ptrace',
                'action': 'BLOCKED',
                'policy_id': policy_id,
                'hook': 'bpf_lsm_ptrace_access_check'
            }
            self.blocked_events.append(evt)
            blocked.append(evt)
        return blocked
    
    def reset(self):
        self.loaded_policies.clear()
        self.blocked_events.clear()

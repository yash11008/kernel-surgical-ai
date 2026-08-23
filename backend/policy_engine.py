import uuid
from datetime import datetime

SYSCALL_HOOKS = {
    'ptrace': 'bpf_lsm_ptrace_access_check',
    'unshare': 'bpf_lsm_cred_prepare',
    'memfd_create': 'bpf_lsm_file_mprotect',
    'setns': 'bpf_lsm_cred_prepare',
    'bpf': 'bpf_lsm_bpf',
}

# Capabilities a standard web-service workload genuinely needs and should
# keep; everything else observed on the workload is surgically restricted.
ESSENTIAL_CAPABILITIES = {'CAP_NET_BIND_SERVICE', 'CAP_KILL'}

# Kernel modules a containerized web workload's runtime substrate typically
# needs; everything else observed is surgically restricted.
ESSENTIAL_MODULES = {'ext4', 'virtio_net', 'virtio_blk', 'overlay'}

HIGH_RISK_SYSCALLS = {'ptrace', 'unshare', 'memfd_create', 'setns', 'bpf'}


class PolicyEngine:
    """Generates and manages the lifecycle of workload-scoped, least-privilege
    BPF-LSM security policies (DRAFT -> DEPLOYED -> VERIFIED / ROLLED_BACK).

    The generated policy is surgical: it restricts exactly the high-risk
    syscalls, non-essential capabilities, and non-essential kernel modules
    observed on THIS workload's profile — not a blanket deny-all."""

    def __init__(self):
        self.policies: list[dict] = []
        self._counter: int = 0

    def generate_policy(self, analysis: dict, profile: dict) -> dict:
        """Generate a workload-scoped least-privilege policy from the
        observed telemetry profile (and, when available, AI analysis)."""
        self._counter += 1
        policy_id = f"KSA-{uuid.uuid4().hex[:4].upper()}"
        target = profile.get('app_name', 'unknown-workload')

        restrictions = []

        observed_syscalls = set(profile.get('syscall_counts', {}).keys())
        for sc in HIGH_RISK_SYSCALLS:
            if sc in observed_syscalls:
                restrictions.append({
                    'type': 'syscall', 'name': sc, 'action': 'DENY',
                    'hook': SYSCALL_HOOKS.get(sc, 'bpf_lsm_task_alloc'),
                })

        for cap in profile.get('capabilities', []):
            if cap not in ESSENTIAL_CAPABILITIES:
                restrictions.append({
                    'type': 'capability', 'name': cap, 'action': 'RESTRICT',
                    'hook': 'bpf_lsm_capable',
                })

        for mod in profile.get('loaded_modules', []):
            if mod not in ESSENTIAL_MODULES:
                restrictions.append({
                    'type': 'module', 'name': mod, 'action': 'DENY',
                    'hook': 'bpf_lsm_kernel_module_request',
                })

        restricted_syscalls = [r['name'] for r in restrictions if r['type'] == 'syscall']
        primary_hook = SYSCALL_HOOKS.get(restricted_syscalls[0], 'bpf_lsm_ptrace_access_check') if restricted_syscalls else 'bpf_lsm_capable'

        policy = {
            'policy_id': policy_id,
            'target': target,
            'trigger': 'Unused high-risk kernel interfaces detected: ' + ', '.join(restricted_syscalls or ['elevated capabilities']),
            'mode': 'ENFORCEMENT',
            'action': 'DENY',
            'scope': 'WORKLOAD',
            'safety': 'ROLLBACK ENABLED',
            'confidence': (analysis or {}).get('confidence', 0.95),
            'bpf_hook': primary_hook,
            'status': 'DRAFT',
            'created_at': datetime.utcnow().isoformat(),
            'details': {'restrictions': restrictions},
        }
        self.policies.append(policy)
        return policy

    def deploy_policy(self, policy_id: str) -> dict:
        policy = self.get_policy(policy_id)
        if policy:
            policy['status'] = 'DEPLOYED'
            policy['deployed_at'] = datetime.utcnow().isoformat()
        return policy

    def verify_policy(self, policy_id: str) -> dict:
        policy = self.get_policy(policy_id)
        if policy:
            policy['status'] = 'VERIFIED'
            policy['verified_at'] = datetime.utcnow().isoformat()
        return policy

    def rollback_policy(self, policy_id: str) -> dict:
        policy = self.get_policy(policy_id)
        if policy:
            policy['status'] = 'ROLLED_BACK'
        return policy

    def get_policies(self) -> list[dict]:
        return self.policies

    def get_policy(self, policy_id: str) -> dict | None:
        for p in self.policies:
            if p['policy_id'] == policy_id:
                return p
        return None

    def reset(self):
        self.policies.clear()
        self._counter = 0

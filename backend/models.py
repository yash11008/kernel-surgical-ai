from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum

class RiskLevel(str, Enum):
    LOW = 'LOW'
    MEDIUM = 'MEDIUM'
    HIGH = 'HIGH'
    CRITICAL = 'CRITICAL'

class EventAction(str, Enum):
    ALLOW = 'ALLOW'
    REVIEW = 'REVIEW'
    BLOCK = 'BLOCK'

class PolicyStatus(str, Enum):
    DRAFT = 'DRAFT'
    REVIEW = 'REVIEW'
    DEPLOYED = 'DEPLOYED'
    VERIFIED = 'VERIFIED'
    ROLLED_BACK = 'ROLLED_BACK'

class TelemetryEvent(BaseModel):
    timestamp: str
    pid: int
    process: str
    event_type: str  # SYSCALL, MODULE, CAPABILITY
    syscall: str
    count: int
    risk_level: RiskLevel
    action: EventAction

class SyscallInfo(BaseModel):
    number: int
    name: str
    subsystem: str
    risk_level: RiskLevel
    security_context: str
    typical_count_per_sec: float = 0.0

class CapabilityInfo(BaseModel):
    bit: int
    name: str
    risk_level: RiskLevel
    description: str
    attack_vector: str

class KernelModuleInfo(BaseModel):
    name: str
    subsystem: str
    risk_level: RiskLevel
    attack_surface: str
    loaded: bool = True

class WorkloadProfile(BaseModel):
    app_name: str = 'demo-web-service'
    pid: int = 1842
    observed_duration_sec: float = 0.0
    total_syscalls: int = 0
    unique_syscalls: int = 0
    high_risk_count: int = 0
    unused_high_risk: int = 0
    capabilities: list[str] = []
    loaded_modules: list[str] = []
    behavioral_confidence: float = 0.0
    syscall_counts: dict[str, int] = {}
    capability_details: list[dict] = []
    module_details: list[dict] = []

class ThreatRecord(BaseModel):
    cve_id: str
    vendor: str
    product: str
    vulnerability_name: str
    severity: str
    cvss_score: float
    short_description: str
    kernel_subsystem: str
    affected_versions: str
    cwe_ids: list[str] = []
    date_added: str = ''
    due_date: str = ''
    cisa_kev: bool = False
    known_ransomware: str = 'Unknown'
    telemetry_indicators: list[str] = []
    required_action: str = ''
    runtime_relevance: str = 'UNKNOWN'

class SecurityAnalysis(BaseModel):
    risk_level: RiskLevel = RiskLevel.LOW
    confidence: float = 0.0
    findings: list[str] = []
    recommendation: str = ''
    relevant_cves: list[str] = []
    relevant_capabilities: list[str] = []
    analysis_steps: list[str] = []
    timestamp: str = ''

class PolicyRecord(BaseModel):
    policy_id: str
    target: str
    trigger: str
    mode: str = 'OBSERVE'  # OBSERVE or ENFORCEMENT
    action: str = 'DENY'
    scope: str = 'WORKLOAD'
    safety: str = 'ROLLBACK ENABLED'
    confidence: float = 0.0
    bpf_hook: str = ''
    status: PolicyStatus = PolicyStatus.DRAFT
    created_at: str = ''
    deployed_at: str | None = None
    verified_at: str | None = None
    details: dict = {}

class ScoreDimension(BaseModel):
    name: str
    weight: float
    raw_score: float
    weighted_score: float
    description: str = ''

class AttackSurfaceScore(BaseModel):
    baseline_score: float = 0.0
    current_score: float = 0.0
    reduction_pct: float = 0.0
    dimensions: list[ScoreDimension] = []
    isolation_multiplier: float = 1.0
    isolation_type: str = 'Standard OCI Container'
    methodology_version: str = '1.0'

class SystemStatus(BaseModel):
    host_online: bool = True
    kernel_version: str = 'Unknown'
    ebpf_active: bool = False
    ebpf_mode: str = 'SIMULATED'
    bpf_lsm_ready: bool = False
    bpf_lsm_mode: str = 'DEMONSTRATION'
    ai_engine_online: bool = True
    ai_mode: str = 'DETERMINISTIC'
    threat_intel_synced: bool = True
    demo_mode: bool = True

class DemoPhase(BaseModel):
    phase_number: int
    name: str
    duration_sec: int
    status: str = 'PENDING'  # PENDING, ACTIVE, COMPLETE
    description: str = ''
    started_at: float | None = None
    completed_at: float | None = None

class AppHealth(BaseModel):
    requests_per_min: int = 100
    success_rate: float = 100.0
    restarts: int = 0
    reboots: int = 0
    uptime_sec: float = 0.0
    start_time: float = 0.0
    total_requests: int = 0
    policy_deployments: int = 0
    availability_pct: float = 100.0

SYSCALL_DATABASE = {
    'read': SyscallInfo(number=0, name='read', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'write': SyscallInfo(number=1, name='write', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'open': SyscallInfo(number=2, name='open', subsystem='fs', risk_level=RiskLevel.MEDIUM, security_context='file_access'),
    'close': SyscallInfo(number=3, name='close', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'stat': SyscallInfo(number=4, name='stat', subsystem='fs', risk_level=RiskLevel.LOW, security_context='metadata'),
    'fstat': SyscallInfo(number=5, name='fstat', subsystem='fs', risk_level=RiskLevel.LOW, security_context='metadata'),
    'lstat': SyscallInfo(number=6, name='lstat', subsystem='fs', risk_level=RiskLevel.LOW, security_context='metadata'),
    'poll': SyscallInfo(number=7, name='poll', subsystem='io', risk_level=RiskLevel.LOW, security_context='events'),
    'lseek': SyscallInfo(number=8, name='lseek', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'mmap': SyscallInfo(number=9, name='mmap', subsystem='mm', risk_level=RiskLevel.MEDIUM, security_context='memory'),
    'mprotect': SyscallInfo(number=10, name='mprotect', subsystem='mm', risk_level=RiskLevel.HIGH, security_context='memory'),
    'munmap': SyscallInfo(number=11, name='munmap', subsystem='mm', risk_level=RiskLevel.LOW, security_context='memory'),
    'brk': SyscallInfo(number=12, name='brk', subsystem='mm', risk_level=RiskLevel.LOW, security_context='memory'),
    'rt_sigaction': SyscallInfo(number=13, name='rt_sigaction', subsystem='signal', risk_level=RiskLevel.LOW, security_context='signals'),
    'ioctl': SyscallInfo(number=16, name='ioctl', subsystem='io', risk_level=RiskLevel.MEDIUM, security_context='device_control'),
    'readv': SyscallInfo(number=19, name='readv', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'writev': SyscallInfo(number=20, name='writev', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'access': SyscallInfo(number=21, name='access', subsystem='fs', risk_level=RiskLevel.LOW, security_context='metadata'),
    'pipe': SyscallInfo(number=22, name='pipe', subsystem='ipc', risk_level=RiskLevel.LOW, security_context='ipc'),
    'madvise': SyscallInfo(number=28, name='madvise', subsystem='mm', risk_level=RiskLevel.MEDIUM, security_context='memory'),
    'dup': SyscallInfo(number=32, name='dup', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'dup2': SyscallInfo(number=33, name='dup2', subsystem='fs', risk_level=RiskLevel.LOW, security_context='basic_io'),
    'nanosleep': SyscallInfo(number=35, name='nanosleep', subsystem='time', risk_level=RiskLevel.LOW, security_context='scheduling'),
    'getpid': SyscallInfo(number=39, name='getpid', subsystem='process', risk_level=RiskLevel.LOW, security_context='info'),
    'sendfile': SyscallInfo(number=40, name='sendfile', subsystem='net', risk_level=RiskLevel.LOW, security_context='io'),
    'socket': SyscallInfo(number=41, name='socket', subsystem='net', risk_level=RiskLevel.MEDIUM, security_context='network'),
    'connect': SyscallInfo(number=42, name='connect', subsystem='net', risk_level=RiskLevel.MEDIUM, security_context='network'),
    'accept': SyscallInfo(number=43, name='accept', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'sendto': SyscallInfo(number=44, name='sendto', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'recvfrom': SyscallInfo(number=45, name='recvfrom', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'sendmsg': SyscallInfo(number=46, name='sendmsg', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'recvmsg': SyscallInfo(number=47, name='recvmsg', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'shutdown': SyscallInfo(number=48, name='shutdown', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'bind': SyscallInfo(number=49, name='bind', subsystem='net', risk_level=RiskLevel.MEDIUM, security_context='network'),
    'listen': SyscallInfo(number=50, name='listen', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'setsockopt': SyscallInfo(number=54, name='setsockopt', subsystem='net', risk_level=RiskLevel.MEDIUM, security_context='network'),
    'clone': SyscallInfo(number=56, name='clone', subsystem='process', risk_level=RiskLevel.HIGH, security_context='process_creation'),
    'fork': SyscallInfo(number=57, name='fork', subsystem='process', risk_level=RiskLevel.MEDIUM, security_context='process_creation'),
    'execve': SyscallInfo(number=59, name='execve', subsystem='process', risk_level=RiskLevel.CRITICAL, security_context='execution'),
    'exit': SyscallInfo(number=60, name='exit', subsystem='process', risk_level=RiskLevel.LOW, security_context='process'),
    'kill': SyscallInfo(number=62, name='kill', subsystem='signal', risk_level=RiskLevel.MEDIUM, security_context='signals'),
    'fcntl': SyscallInfo(number=72, name='fcntl', subsystem='fs', risk_level=RiskLevel.LOW, security_context='file_control'),
    'ptrace': SyscallInfo(number=101, name='ptrace', subsystem='process', risk_level=RiskLevel.CRITICAL, security_context='debugging'),
    'setuid': SyscallInfo(number=105, name='setuid', subsystem='credentials', risk_level=RiskLevel.HIGH, security_context='privilege'),
    'setgid': SyscallInfo(number=106, name='setgid', subsystem='credentials', risk_level=RiskLevel.HIGH, security_context='privilege'),
    'prctl': SyscallInfo(number=157, name='prctl', subsystem='process', risk_level=RiskLevel.HIGH, security_context='process_control'),
    'futex': SyscallInfo(number=202, name='futex', subsystem='ipc', risk_level=RiskLevel.LOW, security_context='sync'),
    'getdents64': SyscallInfo(number=217, name='getdents64', subsystem='fs', risk_level=RiskLevel.LOW, security_context='directory'),
    'epoll_wait': SyscallInfo(number=232, name='epoll_wait', subsystem='io', risk_level=RiskLevel.LOW, security_context='events'),
    'epoll_ctl': SyscallInfo(number=233, name='epoll_ctl', subsystem='io', risk_level=RiskLevel.LOW, security_context='events'),
    'openat': SyscallInfo(number=257, name='openat', subsystem='fs', risk_level=RiskLevel.MEDIUM, security_context='file_access'),
    'unlinkat': SyscallInfo(number=263, name='unlinkat', subsystem='fs', risk_level=RiskLevel.MEDIUM, security_context='file_removal'),
    'unshare': SyscallInfo(number=272, name='unshare', subsystem='namespace', risk_level=RiskLevel.CRITICAL, security_context='namespaces'),
    'accept4': SyscallInfo(number=288, name='accept4', subsystem='net', risk_level=RiskLevel.LOW, security_context='network'),
    'setns': SyscallInfo(number=308, name='setns', subsystem='namespace', risk_level=RiskLevel.CRITICAL, security_context='namespaces'),
    'memfd_create': SyscallInfo(number=319, name='memfd_create', subsystem='mm', risk_level=RiskLevel.HIGH, security_context='memory'),
    'bpf': SyscallInfo(number=321, name='bpf', subsystem='bpf', risk_level=RiskLevel.CRITICAL, security_context='ebpf'),
    'execveat': SyscallInfo(number=322, name='execveat', subsystem='process', risk_level=RiskLevel.CRITICAL, security_context='execution'),
    'userfaultfd': SyscallInfo(number=323, name='userfaultfd', subsystem='mm', risk_level=RiskLevel.HIGH, security_context='memory'),
    'io_uring_setup': SyscallInfo(number=425, name='io_uring_setup', subsystem='io', risk_level=RiskLevel.HIGH, security_context='async_io')
}

CAPABILITY_DATABASE = {
    'CAP_CHOWN': CapabilityInfo(bit=0, name='CAP_CHOWN', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_DAC_OVERRIDE': CapabilityInfo(bit=1, name='CAP_DAC_OVERRIDE', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_DAC_READ_SEARCH': CapabilityInfo(bit=2, name='CAP_DAC_READ_SEARCH', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_FOWNER': CapabilityInfo(bit=3, name='CAP_FOWNER', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_KILL': CapabilityInfo(bit=5, name='CAP_KILL', risk_level=RiskLevel.MEDIUM, description='', attack_vector=''),
    'CAP_SETGID': CapabilityInfo(bit=6, name='CAP_SETGID', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_SETUID': CapabilityInfo(bit=7, name='CAP_SETUID', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_SETPCAP': CapabilityInfo(bit=8, name='CAP_SETPCAP', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_LINUX_IMMUTABLE': CapabilityInfo(bit=9, name='CAP_LINUX_IMMUTABLE', risk_level=RiskLevel.MEDIUM, description='', attack_vector=''),
    'CAP_NET_BIND_SERVICE': CapabilityInfo(bit=10, name='CAP_NET_BIND_SERVICE', risk_level=RiskLevel.LOW, description='', attack_vector=''),
    'CAP_NET_ADMIN': CapabilityInfo(bit=12, name='CAP_NET_ADMIN', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_NET_RAW': CapabilityInfo(bit=13, name='CAP_NET_RAW', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_IPC_LOCK': CapabilityInfo(bit=14, name='CAP_IPC_LOCK', risk_level=RiskLevel.MEDIUM, description='', attack_vector=''),
    'CAP_SYS_MODULE': CapabilityInfo(bit=16, name='CAP_SYS_MODULE', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_SYS_RAWIO': CapabilityInfo(bit=17, name='CAP_SYS_RAWIO', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_SYS_CHROOT': CapabilityInfo(bit=18, name='CAP_SYS_CHROOT', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_SYS_PTRACE': CapabilityInfo(bit=19, name='CAP_SYS_PTRACE', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_SYS_ADMIN': CapabilityInfo(bit=21, name='CAP_SYS_ADMIN', risk_level=RiskLevel.CRITICAL, description='', attack_vector=''),
    'CAP_SYS_TIME': CapabilityInfo(bit=25, name='CAP_SYS_TIME', risk_level=RiskLevel.MEDIUM, description='', attack_vector=''),
    'CAP_MKNOD': CapabilityInfo(bit=27, name='CAP_MKNOD', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_PERFMON': CapabilityInfo(bit=38, name='CAP_PERFMON', risk_level=RiskLevel.HIGH, description='', attack_vector=''),
    'CAP_BPF': CapabilityInfo(bit=39, name='CAP_BPF', risk_level=RiskLevel.CRITICAL, description='', attack_vector='')
}

_modules = ['nf_tables', 'nf_conntrack', 'nf_nat', 'overlay', 'ext4', 'virtio_net', 'virtio_blk', 'br_netfilter', 'veth', 'bridge', 'tun', 'wireguard', 'aesni_intel', 'crypto_simd', 'dm_mod', 'sch_fq_codel', 'loop', 'fuse']
MODULE_DATABASE = {m: KernelModuleInfo(name=m, subsystem='misc', risk_level=RiskLevel.MEDIUM, attack_surface='') for m in _modules}

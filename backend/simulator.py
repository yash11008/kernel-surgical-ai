import time
import random
import threading
from collections import deque, defaultdict
import uuid

class TelemetrySimulator:
    def __init__(self):
        self.events: deque = deque(maxlen=500)
        self.syscall_counts: defaultdict = defaultdict(int)
        self.running: bool = False
        self.start_time: float = 0.0
        self.anomaly_injected: bool = False
        self._lock = threading.Lock()
        self._generation_count: int = 0
        
        self.normal_distribution = {
            'epoll_wait': (50, 150),
            'read': (60, 120),
            'recvmsg': (60, 120),
            'writev': (60, 120),
            'sendmsg': (60, 120),
            'futex': (30, 60),
            'accept4': (20, 50),
            'close': (20, 50),
            'epoll_ctl': (20, 50),
            'fstat': (5, 15),
            'stat': (5, 15),
            'openat': (2, 8),
            'mmap': (0, 2),
            'munmap': (0, 2)
        }
    
    def start(self):
        """Start generating telemetry events."""
        self.running = True
        self.start_time = time.time()
        self._generate_startup_burst()
    
    def stop(self):
        self.running = False
    
    def generate_tick(self):
        """Generate one tick of telemetry (call this periodically).
        This is NOT threaded - the Streamlit app calls this on each refresh."""
        if not self.running:
            return
        self._generation_count += 1
        self._generate_normal_telemetry()
    
    def inject_anomaly(self):
        """Inject controlled anomalous events (ptrace, execve attempt, etc.)."""
        self.anomaly_injected = True
        with self._lock:
            for sys in ['ptrace', 'unshare', 'memfd_create']:
                evt = self._create_event(sys, 1, 'CRITICAL', 'REVIEW')
                self.events.append(evt)
                self.syscall_counts[sys] += 1
    
    def get_events(self, limit: int = 50) -> list[dict]:
        """Return latest events as dicts."""
        with self._lock:
            return list(self.events)[-limit:]
    
    def get_workload_profile(self) -> dict:
        """Compute WorkloadProfile from accumulated telemetry."""
        with self._lock:
            return {
                'app_name': 'demo-web-service',
                'syscall_counts': dict(self.syscall_counts),
                'loaded_modules': ['nf_tables', 'nf_conntrack', 'nf_nat', 'overlay', 'ext4', 
                                   'virtio_net', 'virtio_blk', 'veth', 'bridge', 'dm_mod', 
                                   'loop', 'fuse'],
                'capabilities': ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_FOWNER', 'CAP_SETGID', 
                                 'CAP_SETUID', 'CAP_NET_BIND_SERVICE', 'CAP_NET_RAW', 
                                 'CAP_SYS_CHROOT', 'CAP_KILL']
            }
    
    def get_syscall_summary(self) -> dict[str, int]:
        """Return aggregated syscall counts."""
        with self._lock:
            return dict(self.syscall_counts)
    
    def reset(self):
        """Reset all state."""
        with self._lock:
            self.events.clear()
            self.syscall_counts.clear()
            self.running = False
            self.start_time = 0.0
            self.anomaly_injected = False
            self._generation_count = 0
    
    def _generate_startup_burst(self):
        """Generate realistic startup telemetry burst."""
        with self._lock:
            startup_syscalls = ['openat', 'mmap', 'mprotect', 'rt_sigaction', 'socket', 'bind', 'listen', 'clone']
            for sys in startup_syscalls:
                count = random.randint(10, 50)
                evt = self._create_event(sys, count, 'LOW', 'ALLOW')
                self.events.append(evt)
                self.syscall_counts[sys] += count
    
    def _generate_normal_telemetry(self):
        """Generate one tick of normal web service telemetry."""
        with self._lock:
            for sys, (min_val, max_val) in self.normal_distribution.items():
                count = random.randint(min_val, max_val)
                if count > 0:
                    evt = self._create_event(sys, count, 'LOW', 'ALLOW')
                    self.events.append(evt)
                    self.syscall_counts[sys] += count
    
    def _create_event(self, syscall: str, count: int, risk: str, action: str) -> dict:
        """Create a single telemetry event dict."""
        return {
            'timestamp': time.time(),
            'pid': random.randint(1000, 9999),
            'process': 'demo-web-svc',
            'event_type': 'syscall',
            'syscall': syscall,
            'count': count,
            'risk_level': risk,
            'action': action,
            'id': str(uuid.uuid4())
        }

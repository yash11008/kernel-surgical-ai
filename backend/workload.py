import time
import random


class DemoWorkload:
    """Simulates the live application health of the protected workload
    (demo-web-service) so the dashboard can prove zero-downtime enforcement:
    request throughput keeps flowing, no restarts, no reboots."""

    def __init__(self):
        self.start_time: float = 0.0
        self.running: bool = False
        self.policy_deployments: int = 0
        self.restarts: int = 0
        self.reboots: int = 0
        self.total_requests: int = 0
        self._base_rpm: int = 96

    def start(self):
        self.running = True
        self.start_time = time.time()

    def record_policy_deployment(self):
        self.policy_deployments += 1

    def get_health(self) -> dict:
        elapsed = (time.time() - self.start_time) if self.running else 0.0
        rpm = self._base_rpm + random.randint(-5, 7)
        self.total_requests += max(0, rpm // 20)
        return {
            'requests_per_min': rpm,
            'success_rate': 100.0,
            'restarts': self.restarts,
            'reboots': self.reboots,
            'uptime_sec': elapsed,
            'start_time': self.start_time,
            'total_requests': self.total_requests,
            'policy_deployments': self.policy_deployments,
            'availability_pct': 100.0,
        }

    def reset(self):
        self.start_time = 0.0
        self.running = False
        self.policy_deployments = 0
        self.restarts = 0
        self.reboots = 0
        self.total_requests = 0

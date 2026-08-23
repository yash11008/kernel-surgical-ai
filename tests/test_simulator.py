import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from backend.simulator import TelemetrySimulator

def test_generates_events():
    sim = TelemetrySimulator()
    sim.start()
    sim.generate_tick()
    events = sim.get_events()
    assert len(events) > 0

def test_event_structure():
    sim = TelemetrySimulator()
    sim.start()
    sim.generate_tick()
    events = sim.get_events()
    ev = events[0]
    assert 'timestamp' in ev
    assert 'syscall' in ev
    assert 'risk_level' in ev
    assert 'action' in ev
    assert 'count' in ev

def test_anomaly_injection():
    sim = TelemetrySimulator()
    sim.start()
    sim.inject_anomaly()
    events = sim.get_events()
    injected_syscalls = [e['syscall'] for e in events if e.get('risk_level') == 'CRITICAL']
    assert len(injected_syscalls) > 0
    assert 'ptrace' in injected_syscalls or 'unshare' in injected_syscalls

def test_workload_profile():
    sim = TelemetrySimulator()
    sim.start()
    sim.generate_tick()
    prof = sim.get_workload_profile()
    assert 'app_name' in prof
    assert 'syscall_counts' in prof
    assert 'loaded_modules' in prof
    assert 'capabilities' in prof

def test_reset():
    sim = TelemetrySimulator()
    sim.start()
    sim.inject_anomaly()
    sim.reset()
    assert len(sim.get_events()) == 0
    assert len(sim.syscall_counts) == 0
    assert sim.running is False

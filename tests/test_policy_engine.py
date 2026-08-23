import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from backend.policy_engine import PolicyEngine

def test_generate_policy():
    engine = PolicyEngine()
    profile = {'app_name': 'demo-web-service'}
    analysis = {'risk_level': 'HIGH'}
    pol = engine.generate_policy(analysis, profile)
    assert pol['policy_id'].startswith('KSA-')
    assert pol['target'] == 'demo-web-service'
    assert pol['status'] == 'DRAFT'

def test_policy_status_transitions():
    engine = PolicyEngine()
    profile = {'app_name': 'demo-web-service'}
    analysis = {'risk_level': 'HIGH'}
    pol = engine.generate_policy(analysis, profile)
    pid = pol['policy_id']
    
    assert pol['status'] == 'DRAFT'
    pol = engine.deploy_policy(pid)
    assert pol['status'] == 'DEPLOYED'
    pol = engine.verify_policy(pid)
    assert pol['status'] == 'VERIFIED'

def test_rollback():
    engine = PolicyEngine()
    profile = {'app_name': 'demo-web-service'}
    analysis = {'risk_level': 'HIGH'}
    pol = engine.generate_policy(analysis, profile)
    pid = pol['policy_id']
    
    engine.deploy_policy(pid)
    pol = engine.rollback_policy(pid)
    assert pol['status'] == 'ROLLED_BACK'

def test_policy_id_format():
    engine = PolicyEngine()
    profile = {'app_name': 'demo-web-service'}
    pol = engine.generate_policy({}, profile)
    import re
    assert re.match(r'^KSA-[0-9A-F]+$', pol['policy_id'])

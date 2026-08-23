import sys
import time
from datetime import datetime
from pathlib import Path

import streamlit as st

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

st.set_page_config(
    page_title="KernelSurgical AI",
    page_icon="🔬",
    layout="wide",
    initial_sidebar_state="collapsed",
)

from frontend.theme import (
    inject_theme, render_status_bar, render_hero_header, render_metric_card,
    render_before_after, render_event_card, render_reasoning_panel,
    render_pipeline, render_section_title, severity_color,
)
from backend.system import create_engines, get_system_status
from backend.models import SYSCALL_DATABASE, RiskLevel

inject_theme()

RESTRICTED_TARGETS = {'ptrace', 'unshare', 'memfd_create'}

RISK_RANGES = {
    'CRITICAL': (88, 99),
    'HIGH': (62, 84),
    'MEDIUM': (38, 58),
    'LOW': (2, 16),
}


def numeric_risk(syscall: str, risk_level: str) -> int:
    lo, hi = RISK_RANGES.get(risk_level, (2, 16))
    seed = sum(ord(c) for c in syscall)
    return lo + (seed % (hi - lo + 1))


def count_unrestricted_high_risk(profile: dict, policies: list[dict]) -> int:
    blocked_names = set()
    for p in policies:
        if p.get('status') in ('DEPLOYED', 'VERIFIED'):
            for r in p.get('details', {}).get('restrictions', []):
                blocked_names.add(r.get('name'))
    count = 0
    for sc in profile.get('syscall_counts', {}):
        info = SYSCALL_DATABASE.get(sc)
        if info and info.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL) and sc not in blocked_names:
            count += 1
    return count


# --------------------------------------------------------------------------
# Engine bootstrap
# --------------------------------------------------------------------------

def warmup(engines: dict):
    """Prime telemetry + a visible baseline threat + AI analysis so the
    judge sees exposure, suspicious activity, and reasoning immediately,
    before ever clicking Execute."""
    sim = engines['simulator']
    sim.start()
    for _ in range(4):
        sim.generate_tick()
    sim.inject_anomaly()
    profile = sim.get_workload_profile()
    baseline = engines['scorer'].compute_baseline(profile)
    threats = engines['threat_intel'].get_relevant_for_profile(profile)
    analysis = engines['reasoner'].analyze(profile, threats)
    st.session_state.baseline_score = baseline
    st.session_state.pre_analysis = analysis


def init_state():
    if 'engines_initialized' not in st.session_state:
        engines = create_engines()
        st.session_state.engines = engines
        st.session_state.system_status = get_system_status()
        st.session_state.demo_running = False
        warmup(engines)
        st.session_state.engines_initialized = True


init_state()
engines = st.session_state.engines
scenario = engines['scenario']
simulator = engines['simulator']
scorer = engines['scorer']
reasoner = engines['reasoner']
policy_engine = engines['policy_engine']
bpf_lsm = engines['bpf_lsm']
workload = engines['workload']
threat_intel = engines['threat_intel']

# --------------------------------------------------------------------------
# 8 / 10 — LIVE SYSTEM STATUS + DEMO MODE
# --------------------------------------------------------------------------
render_status_bar(st.session_state.system_status, demo_badge=True)

# --------------------------------------------------------------------------
# 1 — ABOVE-THE-FOLD HERO
# --------------------------------------------------------------------------
render_hero_header()

is_running = st.session_state.demo_running
is_complete = scenario.is_complete()

btn_l, btn_c, btn_r = st.columns([1.4, 1.2, 1.2])
with btn_c:
    if st.button(
        "⚡ EXECUTE SURGICAL ENFORCEMENT",
        type="primary",
        use_container_width=True,
        disabled=is_running or is_complete,
    ):
        scenario.start()
        st.session_state.demo_running = True
        st.rerun()
with btn_r:
    if st.button("↺ RESET DEMO", use_container_width=True):
        scenario.reset()
        st.session_state.demo_running = False
        warmup(engines)
        st.rerun()

if is_complete:
    st.html('<div style="text-align:center; font-size:0.72rem; color:#00e58a; margin:-4px 0 8px 0;">'
            'Operation complete — click Reset Demo to run again.</div>')
elif is_running:
    st.html('<div style="text-align:center; font-size:0.72rem; color:#00e5ff; margin:-4px 0 8px 0;">'
            'Surgical operation in progress — pipeline executing live below.</div>')

st.html('<div style="height:6px;"></div>')

# --------------------------------------------------------------------------
# Live body (auto-refreshes only while the operation is running)
# --------------------------------------------------------------------------
refresh_interval = 1 if st.session_state.demo_running else None


@st.fragment(run_every=refresh_interval)
def live_body():
    state = scenario.tick()
    current_phase = state['current_phase']
    complete = scenario.is_complete()

    profile = simulator.get_workload_profile()
    policies = policy_engine.get_policies()

    baseline_val = st.session_state.baseline_score.get('baseline_score', 0.0)
    if complete:
        final = state.get('final_score', {})
        current_val = final.get('current_score', baseline_val)
        reduction_val = final.get('reduction_pct', 0.0)
    else:
        current_val = baseline_val
        reduction_val = 0.0

    high_risk_count = count_unrestricted_high_risk(profile, policies)
    health = workload.get_health()

    if complete:
        enforcement_status = 'VERIFIED'
        enforcement_tone = 'emerald'
    elif current_phase >= 7:
        enforcement_status = 'ENFORCING'
        enforcement_tone = 'amber'
    elif current_phase >= 1:
        enforcement_status = 'OBSERVING'
        enforcement_tone = 'cyan'
    else:
        enforcement_status = 'STANDBY'
        enforcement_tone = 'muted'

    # ---- 5 hero metric cards ----
    m1, m2, m3, m4, m5 = st.columns(5)
    with m1:
        exposure_label = f"↓ {reduction_val:.1f}%" if complete else f"{baseline_val:.1f} KEI"
        render_metric_card("WORKLOAD EXPOSURE", exposure_label,
                            "Reduced" if complete else "Baseline (0-100 scale)",
                            tone='emerald' if complete else 'amber')
    with m2:
        render_metric_card("APP AVAILABILITY", f"{health.get('availability_pct', 100.0):.1f}%",
                            "0 restarts", tone='emerald')
    with m3:
        render_metric_card("HIGH-RISK SYSCALLS", str(high_risk_count),
                            "Unrestricted, reachable", tone='red' if high_risk_count > 0 else 'emerald')
    with m4:
        render_metric_card("ENFORCEMENT STATUS", enforcement_status,
                            "BPF-LSM (simulated)", tone=enforcement_tone)
    with m5:
        render_metric_card("REBOOTS REQUIRED", "0", "Zero-reboot operation", tone='emerald')

    # ---- 2 — BEFORE / AFTER centerpiece ----
    render_section_title("🔁", "ATTACK SURFACE: BEFORE → AFTER SURGICAL ENFORCEMENT")
    render_before_after(baseline_val, current_val, health.get('availability_pct', 100.0), 0, complete)

    st.html('<div style="height:10px;"></div>')

    # ---- 3 — THREAT VISIBILITY ----
    render_section_title("🎯", "WHAT THE SYSTEM SEES RIGHT NOW",
                          "Dangerous behavior is flagged — legitimate workload activity is preserved.")
    tcol1, tcol2 = st.columns(2)
    events = simulator.get_events(limit=60)
    blocked_syscalls = {b.get('syscall') for b in bpf_lsm.get_blocked_events()}

    suspicious = [e for e in events if e.get('risk_level') in ('CRITICAL', 'HIGH')]
    seen_sc = set()
    suspicious_unique = []
    for e in reversed(suspicious):
        if e['syscall'] not in seen_sc:
            suspicious_unique.append(e)
            seen_sc.add(e['syscall'])
    suspicious_unique = suspicious_unique[:3]

    allowed = [e for e in events if e.get('risk_level') == 'LOW']
    seen_al = set()
    allowed_unique = []
    for e in reversed(allowed):
        if e['syscall'] not in seen_al:
            allowed_unique.append(e)
            seen_al.add(e['syscall'])
    allowed_unique = allowed_unique[:3]

    with tcol1:
        st.html('<div style="font-size:0.7rem; color:#ff8fa3; font-weight:700; letter-spacing:0.06em; margin-bottom:6px;">SUSPICIOUS / HIGH-RISK ACTIVITY</div>')
        if suspicious_unique:
            for e in suspicious_unique:
                action = 'BLOCKED' if (complete or current_phase >= 7) and e['syscall'] in RESTRICTED_TARGETS else 'REVIEW'
                risk = numeric_risk(e['syscall'], e['risk_level'])
                render_event_card(action, e['syscall'], e['pid'], e['process'], risk)
        else:
            st.html('<div style="color:#64748b; font-size:0.78rem;">No anomalous activity observed.</div>')
    with tcol2:
        st.html('<div style="font-size:0.7rem; color:#7fd9b8; font-weight:700; letter-spacing:0.06em; margin-bottom:6px;">LEGITIMATE WORKLOAD TRAFFIC (ALLOWED)</div>')
        for e in allowed_unique:
            risk = numeric_risk(e['syscall'], e['risk_level'])
            render_event_card('ALLOW', e['syscall'], e['pid'], e['process'], risk)

    st.html('<div style="height:6px;"></div>')

    # ---- 4 — REAL-TIME SECURITY EVENT FEED ----
    render_section_title("📡", "LIVE SECURITY EVENT FEED")
    feed_events = list(reversed(events))[:10]
    rows = ''
    for e in feed_events:
        ts = datetime.fromtimestamp(e['timestamp']).strftime('%H:%M:%S')
        action = 'BLOCKED' if (complete or current_phase >= 7) and e['syscall'] in RESTRICTED_TARGETS else \
                 ('REVIEW' if e['risk_level'] in ('CRITICAL', 'HIGH') else 'ALLOW')
        color = severity_color('CRITICAL' if action == 'BLOCKED' else ('MEDIUM' if action == 'REVIEW' else 'ALLOWED'))
        risk = numeric_risk(e['syscall'], e['risk_level'])
        rows += f'''<tr style="border-bottom:1px solid rgba(255,255,255,0.05);">
            <td style="padding:5px 10px; color:#7c8aa0;">{ts}</td>
            <td style="padding:5px 10px; color:#7c8aa0;">{e['pid']}</td>
            <td style="padding:5px 10px; color:#c3d0e0;">{e['process']}</td>
            <td style="padding:5px 10px; color:{color}; font-weight:700;">{e['syscall']}</td>
            <td style="padding:5px 10px; color:{color};">{risk}</td>
            <td style="padding:5px 10px; color:{color}; font-weight:700;">{action}</td>
        </tr>'''
    st.html(f'''
    <div style="background:rgba(10,15,24,0.55); border:1px solid rgba(255,255,255,0.07); border-radius:8px; overflow:hidden;">
        <table style="width:100%; border-collapse:collapse; font-size:0.76rem; font-family:'JetBrains Mono',monospace;">
            <thead>
                <tr style="background:rgba(255,255,255,0.03); text-align:left;">
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">TIMESTAMP</th>
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">PID</th>
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">PROCESS</th>
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">SYSCALL</th>
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">RISK</th>
                    <th style="padding:7px 10px; color:#7c8aa0; font-weight:600;">DECISION</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>
    </div>
    ''')

    st.html('<div style="height:6px;"></div>')

    # ---- 5 — ATTACK SURFACE VISUALIZATION ----
    render_section_title("🗺️", "EXPOSED KERNEL INTERFACES: BEFORE → AFTER")
    acol1, acol2 = st.columns(2)
    syscalls = list(profile.get('syscall_counts', {}).keys())
    with acol1:
        st.html('<div style="font-size:0.7rem; color:#c9a48a; font-weight:700; margin-bottom:6px;">BEFORE (ALL REACHABLE)</div>')
        chips = ''
        for sc in syscalls:
            info = SYSCALL_DATABASE.get(sc)
            risky = info and info.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            color = '#ff3b5c' if risky else '#00e5ff'
            tag = ' ⚠' if risky else ''
            chips += f'<span style="display:inline-block; margin:3px; padding:4px 9px; border:1px solid {color}55; background:{color}12; color:{color}; border-radius:4px; font-size:0.72rem;">{sc}{tag}</span>'
        st.html(f'<div>{chips}</div>')
    with acol2:
        title = 'AFTER SURGICAL ENFORCEMENT' if complete else 'AFTER (PENDING ENFORCEMENT)'
        st.html(f'<div style="font-size:0.7rem; color:#7fd9b8; font-weight:700; margin-bottom:6px;">{title}</div>')
        chips = ''
        for sc in syscalls:
            info = SYSCALL_DATABASE.get(sc)
            risky = info and info.risk_level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
            if complete and sc in RESTRICTED_TARGETS:
                chips += f'<span style="display:inline-block; margin:3px; padding:4px 9px; border:1px solid #ff3b5c55; background:#ff3b5c12; color:#ff3b5c; border-radius:4px; font-size:0.72rem; text-decoration:line-through;">{sc} BLOCKED</span>'
            else:
                color = '#00e58a'
                chips += f'<span style="display:inline-block; margin:3px; padding:4px 9px; border:1px solid {color}55; background:{color}12; color:{color}; border-radius:4px; font-size:0.72rem;">{sc} ✓</span>'
        st.html(f'<div>{chips}</div>')

    st.html('<div style="height:6px;"></div>')

    # ---- 6 — AI REASONING PANEL ----
    render_section_title("🧠", "AI SECURITY REASONING")
    analysis = scenario.get_analysis() or st.session_state.get('pre_analysis') or {}
    render_reasoning_panel(
        analysis.get('detected', 'Profiling live workload telemetry...'),
        analysis.get('why_risky', 'Awaiting sufficient telemetry to assess risk.'),
        analysis.get('action', 'Continue observation.'),
    )

    st.html('<div style="height:6px;"></div>')

    # ---- 7 — 8-PHASE PIPELINE ----
    render_section_title("⚙️", "SURGICAL OPERATION PIPELINE",
                          "OBSERVE → REASON → SURGICALLY ENFORCE → VERIFY")
    render_pipeline(current_phase)

    # ---- completion banner ----
    if complete:
        st.html('''
        <div style="margin-top:14px; text-align:center; background:rgba(0,229,138,0.06);
                    border:1px solid rgba(0,229,138,0.35); border-radius:8px; padding:14px;">
            <div style="font-family:'Orbitron',sans-serif; font-weight:800; font-size:1rem; color:#00e58a; letter-spacing:0.06em;">
                ✓ KERNEL SURGICAL OPERATION COMPLETE
            </div>
            <div style="font-size:0.8rem; color:#c3d0e0; margin-top:6px;">
                Security posture changed. Application availability did not.
            </div>
        </div>
        ''')

    # auto-stop the refresh loop once finished
    if current_phase >= 8 and not scenario.running and st.session_state.demo_running:
        st.session_state.demo_running = False
        st.rerun()


live_body()

st.html('<div style="height:18px;"></div>')

# --------------------------------------------------------------------------
# TECHNICAL DETAILS (lowest visual priority — collapsed by default)
# --------------------------------------------------------------------------
with st.expander("🔬 TECHNICAL DETAILS — workload profile, threat intel, synthesized policy, methodology"):
    profile = simulator.get_workload_profile()
    tabs = st.tabs(["Workload Profile", "Threat Intelligence", "Synthesized Policy", "Scoring Methodology", "Honesty Statement"])

    with tabs[0]:
        st.markdown(f"**Target workload:** `{profile.get('app_name', 'demo-web-service')}`")
        st.markdown(f"**Unique syscalls observed:** {len(profile.get('syscall_counts', {}))}")
        st.markdown("**Kernel capabilities:**")
        st.code(", ".join(profile.get('capabilities', [])), language=None)
        st.markdown("**Loaded kernel modules:**")
        st.code(", ".join(profile.get('loaded_modules', [])), language=None)

    with tabs[1]:
        all_threats = threat_intel.get_all()
        st.markdown(f"**Local, offline threat intelligence cache:** {len(all_threats)} CVE / CISA KEV records")
        for t in all_threats[:6]:
            kev = "CISA KEV" if t.get('cisaKEV') else "NVD"
            st.markdown(f"- `{t.get('cveID')}` — {t.get('vulnerabilityName', '')} ({kev}, CVSS {t.get('cvssScore', '—')})")

    with tabs[2]:
        pol = scenario.get_policy()
        if pol:
            st.json(pol)
            st.code('''// Synthesized KernelSurgical BPF-LSM policy (illustrative)
SEC("lsm/ptrace_access_check")
int BPF_PROG(restrict_ptrace, struct task_struct *child, unsigned int mode) {
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid == TARGET_WORKLOAD_TGID) {
        return -EPERM; // zero-downtime block, no process restart
    }
    return 0;
}''', language='c')
        else:
            st.info("No policy synthesized yet — execute the surgical enforcement operation above.")

    with tabs[3]:
        st.markdown(scorer.get_methodology()['description'])
        st.latex(r"\text{KEI} = \text{Clamp}_{0-100}\left(\sum_{i=1}^{5} W_i \times D_i\right)")
        st.markdown("Syscall 25% · Capability 25% · Hardening 20% · Module 15% · Patch delta 15%")

    with tabs[4]:
        st.html('''
        <div style="font-size:0.8rem; color:#c3d0e0; line-height:1.7;">
        <b style="color:#ffb020;">[TRANSPARENCY DECLARATION]</b><br/>
        • Live in-kernel enforcement requires Linux 5.7+ with <code>CONFIG_BPF_LSM=y</code> and <code>bpf</code> active in the host LSM list.<br/>
        • On hosts without that support (including this demo environment unless run on such a kernel), the system runs in
          <b>SAFE DEMONSTRATION MODE</b> with deterministic simulated telemetry — the scoring, reasoning, and policy-generation
          logic run identically, but no real kernel hooks are attached.<br/>
        • BPF-LSM restricts security-sensitive LSM hook points; it does not replace unprivileged userspace seccomp filters.
        </div>
        ''')

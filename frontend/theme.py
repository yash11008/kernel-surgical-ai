import streamlit as st

SEVERITY_COLORS = {
    'CRITICAL': '#ff3b5c',
    'HIGH': '#ff9100',
    'MEDIUM': '#ffd166',
    'LOW': '#00e5ff',
    'ALLOWED': '#00e58a',
    'NOMINAL': '#00e58a',
}


def severity_color(level: str) -> str:
    return SEVERITY_COLORS.get((level or '').upper(), '#64748b')


def inject_theme():
    """Inject the KernelSurgical AI SOC console theme. Restrained dark-slate
    surfaces with cyan/emerald highlights and red/orange threat states —
    built to read as a purpose-built security product, not a Streamlit
    default template."""
    st.html('''
    <style>
    @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@300;400;500;600;700&family=Orbitron:wght@600;700;800;900&display=swap');

    :root {
        --bg-void: #05070d;
        --bg-panel: rgba(14, 20, 32, 0.72);
        --bg-panel-solid: #0c121e;
        --border-subtle: rgba(0, 229, 255, 0.14);
        --border-glow: rgba(0, 229, 255, 0.4);
        --cyan: #00e5ff;
        --emerald: #00e58a;
        --amber: #ff9100;
        --red: #ff3b5c;
        --text-primary: #e5edf5;
        --text-muted: #7c8aa0;
    }

    .stApp {
        background: radial-gradient(ellipse 1400px 700px at 50% -10%, #0c1a2e 0%, var(--bg-void) 65%);
        color: var(--text-primary);
    }
    html, body, [class*="css"] { font-family: 'JetBrains Mono', 'Consolas', monospace; }

    /* Strip default Streamlit chrome */
    header[data-testid="stHeader"] { background: transparent !important; height: 0; }
    #MainMenu, footer, [data-testid="stToolbar"] { visibility: hidden; height: 0; }
    section[data-testid="stSidebar"] { display: none; }
    .block-container { padding-top: 1.2rem; padding-bottom: 2.5rem; max-width: 1360px; }
    div[data-testid="stVerticalBlockBorderWrapper"] > div { gap: 0; }

    /* Buttons */
    .stButton > button {
        font-family: 'JetBrains Mono', monospace;
        font-weight: 700;
        letter-spacing: 0.06em;
        border-radius: 6px;
        transition: all 0.15s ease;
    }
    .stButton > button[kind="primary"] {
        background: linear-gradient(135deg, rgba(0,229,255,0.22), rgba(0,229,138,0.14)) !important;
        border: 1px solid rgba(0, 229, 255, 0.55) !important;
        color: #d6faff !important;
        box-shadow: 0 0 18px rgba(0, 229, 255, 0.12);
    }
    .stButton > button[kind="primary"]:hover { box-shadow: 0 0 26px rgba(0, 229, 255, 0.28); }
    .stButton > button[kind="secondary"] {
        background: rgba(255,255,255,0.03) !important;
        border: 1px solid rgba(255,255,255,0.12) !important;
        color: var(--text-muted) !important;
    }

    /* Tabs / expanders kept minimal */
    .stTabs [data-baseweb="tab"] { font-family: 'JetBrains Mono', monospace; font-size: 0.78rem; letter-spacing: 0.04em; }
    .streamlit-expanderHeader { font-family: 'JetBrains Mono', monospace; font-size: 0.82rem; }
    [data-testid="stExpander"] { border: 1px solid rgba(255,255,255,0.08); border-radius: 8px; background: rgba(10,15,24,0.5); }

    ::-webkit-scrollbar { width: 6px; height: 6px; }
    ::-webkit-scrollbar-track { background: var(--bg-void); }
    ::-webkit-scrollbar-thumb { background: #1c2a3d; border-radius: 3px; }
    ::-webkit-scrollbar-thumb:hover { background: var(--cyan); }

    @keyframes ks-pulse { 0%,100% { opacity: 1; } 50% { opacity: 0.45; } }
    </style>
    ''')


def render_status_bar(status: dict, demo_badge: bool = True):
    ebpf_mode = status.get('ebpf_mode', 'SIMULATED')
    lsm_mode = status.get('bpf_lsm_mode', 'SIMULATED')
    ai_mode = status.get('ai_mode', 'DETERMINISTIC')

    chips = [
        ('TELEMETRY STREAM', 'ACTIVE', True),
        ('AI REASONING', 'READY', True),
        ('POLICY ENGINE', 'READY', True),
        ('BPF-LSM', lsm_mode, lsm_mode == 'LIVE'),
        ('APPLICATION', 'HEALTHY', True),
    ]
    chip_html = ''
    for label, val, active in chips:
        color = '#00e58a' if active else '#ffb020'
        chip_html += f'''
        <span style="display:inline-flex;align-items:center;gap:6px;margin-right:18px;font-size:0.68rem;color:var(--text-muted);letter-spacing:0.04em;">
            <span style="width:6px;height:6px;border-radius:50%;background:{color};box-shadow:0 0 6px {color};display:inline-block;"></span>
            {label}: <span style="color:{color};font-weight:700;">{val}</span>
        </span>'''

    badge_html = ''
    if demo_badge:
        badge_html = '''
        <span style="background:rgba(255,145,0,0.12); border:1px solid rgba(255,145,0,0.5); color:#ffb020;
                     padding:3px 10px; border-radius:4px; font-size:0.68rem; font-weight:700; letter-spacing:0.08em;">
            ● DEMO MODE — SAFE SIMULATION, NO LIVE HOST ENFORCEMENT
        </span>'''

    st.html(f'''
    <div style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px;
                background:rgba(12,18,30,0.6); border:1px solid rgba(255,255,255,0.06);
                border-radius:6px; padding:8px 16px; margin-bottom:14px;">
        <div>{chip_html}</div>
        <div>{badge_html}</div>
    </div>
    ''')


def render_hero_header():
    st.html('''
    <div style="text-align:center; padding: 0.4rem 0 1.1rem 0;">
        <div style="font-family:'Orbitron',sans-serif; font-weight:900; font-size:2.1rem; letter-spacing:0.12em;
                    color:#eaf8ff; text-shadow: 0 0 26px rgba(0,229,255,0.28);">
            🔬 KERNELSURGICAL <span style="color:var(--cyan);">AI</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:#9fb0c4; margin-top:6px; letter-spacing:0.02em;">
            Dynamic Kernel Attack Surface Reduction &amp; Zero-Downtime Auto-Remediation
        </div>
        <div style="display:flex; justify-content:center; gap:10px; margin-top:16px; flex-wrap:wrap;">
            <span style="font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:0.1em; color:var(--cyan);
                         border:1px solid rgba(0,229,255,0.35); background:rgba(0,229,255,0.06);
                         padding:5px 12px; border-radius:4px;">OBSERVE</span>
            <span style="color:#3a4a5f; align-self:center;">→</span>
            <span style="font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:0.1em; color:#c9a6ff;
                         border:1px solid rgba(168,85,247,0.35); background:rgba(168,85,247,0.06);
                         padding:5px 12px; border-radius:4px;">REASON</span>
            <span style="color:#3a4a5f; align-self:center;">→</span>
            <span style="font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:0.1em; color:#ffb020;
                         border:1px solid rgba(255,145,0,0.35); background:rgba(255,145,0,0.06);
                         padding:5px 12px; border-radius:4px;">SURGICALLY ENFORCE</span>
            <span style="color:#3a4a5f; align-self:center;">→</span>
            <span style="font-family:'Orbitron',sans-serif; font-size:0.72rem; letter-spacing:0.1em; color:#00e58a;
                         border:1px solid rgba(0,229,138,0.35); background:rgba(0,229,138,0.06);
                         padding:5px 12px; border-radius:4px;">VERIFY</span>
        </div>
    </div>
    ''')


def render_metric_card(label: str, value: str, sublabel: str = '', tone: str = 'cyan'):
    tone_colors = {
        'cyan': '#00e5ff', 'emerald': '#00e58a', 'amber': '#ff9100', 'red': '#ff3b5c', 'muted': '#9fb0c4'
    }
    color = tone_colors.get(tone, '#00e5ff')
    st.html(f'''
    <div style="background:var(--bg-panel); border:1px solid rgba(255,255,255,0.07); border-radius:8px;
                padding:14px 16px; height:100%; box-shadow: inset 0 0 24px rgba(0,0,0,0.35);">
        <div style="font-family:'Orbitron',sans-serif; font-size:0.62rem; letter-spacing:0.09em; color:var(--text-muted);
                    text-transform:uppercase; margin-bottom:8px;">{label}</div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:1.7rem; font-weight:700; color:{color};
                    text-shadow: 0 0 14px {color}33; line-height:1.1;">{value}</div>
        <div style="font-size:0.68rem; color:var(--text-muted); margin-top:5px;">{sublabel}</div>
    </div>
    ''')


def render_before_after(baseline: float, current: float, availability: float, reboots: int, enforced: bool):
    if enforced:
        left_val, left_tag, left_color = f'{baseline:.1f}', 'HIGH', '#ff9100'
        right_val, right_tag, right_color = f'{current:.1f}', 'HARDENED', '#00e58a'
    else:
        left_val, left_tag, left_color = f'{baseline:.1f}', 'HIGH', '#ff9100'
        right_val, right_tag, right_color = '—', 'PENDING', '#64748b'

    st.html(f'''
    <div style="display:grid; grid-template-columns: 1fr auto 1fr; gap:14px; align-items:stretch; margin: 6px 0 4px 0;">
        <div style="background:rgba(255,145,0,0.05); border:1px solid rgba(255,145,0,0.35); border-radius:10px;
                    padding:18px; text-align:center;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.68rem; letter-spacing:0.08em; color:#c9a48a;">
                WORKLOAD EXPOSURE — BEFORE</div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:2.6rem; font-weight:900; color:{left_color};
                        margin:8px 0 2px 0;">{left_val}</div>
            <div style="font-size:0.72rem; font-weight:700; letter-spacing:0.08em; color:{left_color};">{left_tag}</div>
        </div>
        <div style="align-self:center; font-size:1.6rem; color:{'#00e58a' if enforced else '#3a4a5f'};">→</div>
        <div style="background:rgba(0,229,138,0.05); border:1px solid {'rgba(0,229,138,0.4)' if enforced else 'rgba(255,255,255,0.08)'};
                    border-radius:10px; padding:18px; text-align:center;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.68rem; letter-spacing:0.08em; color:#7fd9b8;">
                WORKLOAD EXPOSURE — AFTER SURGICAL ENFORCEMENT</div>
            <div style="font-family:'JetBrains Mono',monospace; font-size:2.6rem; font-weight:900; color:{right_color};
                        margin:8px 0 2px 0;">{right_val}</div>
            <div style="font-size:0.72rem; font-weight:700; letter-spacing:0.08em; color:{right_color};">{right_tag}</div>
        </div>
    </div>
    <div style="display:flex; justify-content:center; gap:36px; margin-top:6px; font-size:0.75rem; color:var(--text-muted);">
        <span>APP AVAILABILITY: <span style="color:#00e58a; font-weight:700;">{availability:.1f}%</span></span>
        <span>REBOOTS: <span style="color:#00e58a; font-weight:700;">{reboots}</span></span>
    </div>
    ''')


def render_event_card(action: str, syscall: str, pid: int, process: str, risk: int, timestamp: str = ''):
    if action == 'BLOCKED':
        border, bg, tag_color, tag = '#ff3b5c', 'rgba(255,59,92,0.07)', '#ff3b5c', 'BLOCKED'
        head = 'CRITICAL'
    elif action == 'REVIEW':
        border, bg, tag_color, tag = '#ffd166', 'rgba(255,209,102,0.07)', '#ffd166', 'REVIEW'
        head = 'MEDIUM'
    else:
        border, bg, tag_color, tag = '#00e58a', 'rgba(0,229,138,0.06)', '#00e58a', 'ALLOWED'
        head = 'ALLOWED'

    ts = f'<div style="font-size:0.62rem; color:var(--text-muted); margin-top:4px;">{timestamp}</div>' if timestamp else ''
    st.html(f'''
    <div style="background:{bg}; border:1px solid {border}44; border-left:3px solid {border};
                border-radius:6px; padding:10px 12px; margin-bottom:8px;">
        <div style="display:flex; justify-content:space-between; align-items:center;">
            <span style="font-size:0.65rem; font-weight:800; letter-spacing:0.06em; color:{tag_color};">{head}</span>
            <span style="font-size:0.62rem; font-weight:700; color:{tag_color}; background:{tag_color}1a;
                         padding:2px 7px; border-radius:3px;">{tag}</span>
        </div>
        <div style="font-family:'JetBrains Mono',monospace; font-size:0.85rem; color:var(--text-primary); margin-top:6px;">
            <code style="color:{tag_color};">{syscall}</code>
        </div>
        <div style="font-size:0.68rem; color:var(--text-muted); margin-top:3px;">PID {pid} · {process} · Risk {risk}</div>
        {ts}
    </div>
    ''')


def render_reasoning_panel(detected: str, why_risky: str, action: str):
    st.html(f'''
    <div style="display:grid; grid-template-columns: 1fr 1fr 1fr; gap:12px;">
        <div style="background:var(--bg-panel); border:1px solid rgba(0,229,255,0.22); border-radius:8px; padding:14px;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.65rem; letter-spacing:0.08em; color:var(--cyan); margin-bottom:8px;">DETECTED</div>
            <div style="font-size:0.82rem; color:var(--text-primary); line-height:1.5;">{detected}</div>
        </div>
        <div style="background:var(--bg-panel); border:1px solid rgba(255,59,92,0.22); border-radius:8px; padding:14px;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.65rem; letter-spacing:0.08em; color:var(--red); margin-bottom:8px;">WHY RISKY</div>
            <div style="font-size:0.82rem; color:var(--text-primary); line-height:1.5;">{why_risky}</div>
        </div>
        <div style="background:var(--bg-panel); border:1px solid rgba(0,229,138,0.22); border-radius:8px; padding:14px;">
            <div style="font-family:'Orbitron',sans-serif; font-size:0.65rem; letter-spacing:0.08em; color:var(--emerald); margin-bottom:8px;">ACTION</div>
            <div style="font-size:0.82rem; color:var(--text-primary); line-height:1.5;">{action}</div>
        </div>
    </div>
    ''')


def render_pipeline(current_phase: int):
    phases = ['TELEMETRY', 'PROFILE', 'MAP', 'CORRELATE', 'REASON', 'GENERATE POLICY', 'ENFORCE', 'VERIFY']
    items = ''
    for i, name in enumerate(phases):
        n = i + 1
        if n < current_phase or (n <= current_phase and current_phase >= 8):
            color, bg, border, icon = '#00e58a', 'rgba(0,229,138,0.08)', 'rgba(0,229,138,0.4)', '✓'
        elif n == current_phase:
            color, bg, border, icon = '#00e5ff', 'rgba(0,229,255,0.1)', 'rgba(0,229,255,0.55)', '►'
        else:
            color, bg, border, icon = '#4a5871', 'rgba(255,255,255,0.02)', 'rgba(255,255,255,0.08)', '○'
        pulse = 'animation: ks-pulse 1.4s ease-in-out infinite;' if n == current_phase else ''
        items += f'''
        <div style="flex:1; min-width:88px; text-align:center; background:{bg}; border:1px solid {border};
                    border-radius:6px; padding:10px 6px; {pulse}">
            <div style="font-size:0.95rem; color:{color};">{icon}</div>
            <div style="font-family:'Orbitron',sans-serif; font-size:0.58rem; letter-spacing:0.04em; color:{color};
                        font-weight:700; margin-top:4px;">{n:02d} {name}</div>
        </div>'''
        if i < len(phases) - 1:
            arrow_color = '#00e58a' if n < current_phase else '#22303f'
            items += f'<div style="align-self:center; color:{arrow_color}; font-size:0.85rem; padding:0 2px;">→</div>'

    st.html(f'<div style="display:flex; align-items:stretch; gap:4px; flex-wrap:wrap;">{items}</div>')


def render_section_title(icon: str, title: str, subtitle: str = ''):
    sub = f'<div style="font-size:0.74rem; color:var(--text-muted); margin-top:2px;">{subtitle}</div>' if subtitle else ''
    st.html(f'''
    <div style="margin: 22px 0 10px 0;">
        <div style="font-family:'Orbitron',sans-serif; font-size:0.85rem; font-weight:700; letter-spacing:0.06em; color:#dbeeff;">
            {icon} {title}</div>
        {sub}
    </div>
    ''')

"""
cyberresilient/theme.py

Centralised theme colours and professional UI components
for the CyberResilient GRC platform.
"""

import streamlit as st
import plotly.io as pio
import plotly.graph_objects as go

THEME_COLORS = {
    "accent": "#D4AF37",        # Gold
    "accent_dark": "#B8960C",   # Darker gold for hover
    "accent_light": "#F0D878",  # Light gold for text highlights
    "bg_dark": "#0E1117",
    "bg_card": "#161B22",
    "bg_card_hover": "#1C2333",
    "bg_surface": "#0D1117",
    "border": "#30363D",
    "border_accent": "#D4AF3740",
    "text_primary": "#EAEAEA",
    "text_secondary": "#8B949E",
    "text_muted": "#6E7681",
    "success": "#3FB950",
    "success_bg": "#3FB95015",
    "warning": "#D29922",
    "warning_bg": "#D2992215",
    "error": "#F85149",
    "error_bg": "#F8514915",
    "info": "#58A6FF",
    "info_bg": "#58A6FF15",
}


def get_theme_colors() -> dict[str, str]:
    """Return the active theme colour palette."""
    return THEME_COLORS.copy()


# ── Professional CSS ──────────────────────────────────────────

_PLATFORM_CSS = """
<style>
/* ── Global Overrides ────────────────────────────────────── */
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    line-height: 1.5;
}

h1, h2, h3 {
    letter-spacing: -0.02em;
}

h1 { font-size: 2rem; }
h2 { font-size: 1.45rem; }
h3 { font-size: 1.2rem; }

p, li, .stMarkdown {
    font-size: 0.95rem;
}

/* Hide default Streamlit header & footer */
header[data-testid="stHeader"] {
    background: linear-gradient(135deg, #0D1117 0%, #161B22 100%);
    border-bottom: 1px solid #30363D;
}

footer { visibility: hidden; }
.stDeployButton { display: none; }

/* Main container spacing */
.block-container {
    padding-top: 1.5rem;
    padding-bottom: 1.5rem;
    max-width: 1200px;
}

.cr-page-header {
    background: linear-gradient(135deg, #161B22 0%, #1C2333 50%, #161B22 100%);
    border: 1px solid #30363D;
    border-radius: 16px;
    padding: 1.6rem 1.9rem;
    margin-bottom: 1.25rem;
    position: relative;
    overflow: hidden;
}

.cr-page-header h1 {
    margin: 0;
    padding: 0;
    font-size: 1.7rem;
    font-weight: 700;
    color: #EAEAEA;
}

.cr-page-subtitle {
    margin: 0.25rem 0 0 0;
    color: #8B949E;
    font-size: 0.92rem;
}

/* ── Sidebar Branding ────────────────────────────────────── */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0D1117 0%, #161B22 50%, #0D1117 100%);
    border-right: 1px solid #30363D;
}

section[data-testid="stSidebar"] > div {
    background:
        radial-gradient(circle at top left, rgba(88, 166, 255, 0.14), transparent 22%),
        radial-gradient(circle at 85% 18%, rgba(63, 185, 80, 0.12), transparent 18%),
        radial-gradient(circle at bottom right, rgba(210, 153, 34, 0.14), transparent 22%),
        linear-gradient(180deg, #0B1220 0%, #121A27 52%, #0D1117 100%);
}

section[data-testid="stSidebar"] .stMarkdown h2 {
    color: #D4AF37;
    font-weight: 700;
    letter-spacing: -0.02em;
}

section[data-testid="stSidebar"] .stMarkdown p strong {
    color: #EAEAEA;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNav"] {
    padding-top: 0.75rem;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNav"]::before {
    content: "Executive Command Rail";
    display: block;
    margin: 0.35rem 0 0.9rem 0;
    padding: 0.55rem 0.8rem;
    border: 1px solid rgba(255, 255, 255, 0.08);
    border-radius: 999px;
    background: linear-gradient(90deg, rgba(88, 166, 255, 0.16), rgba(63, 185, 80, 0.12), rgba(210, 153, 34, 0.16));
    color: #DCE7F3;
    font-size: 0.74rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.12em;
    text-align: center;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavItems"] {
    gap: 0.45rem;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] {
    position: relative;
    margin-bottom: 0.45rem;
    padding: 0.78rem 0.9rem 0.78rem 1rem;
    border-radius: 14px;
    border: 1px solid rgba(255, 255, 255, 0.05);
    background: linear-gradient(135deg, rgba(255, 255, 255, 0.03), rgba(255, 255, 255, 0.01));
    backdrop-filter: blur(6px);
    transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease, background 0.18s ease;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]::before {
    content: "";
    position: absolute;
    top: 10px;
    bottom: 10px;
    left: 8px;
    width: 4px;
    border-radius: 999px;
    background: linear-gradient(180deg, #58A6FF, #3FB950, #D29922);
    opacity: 0.85;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] p {
    color: #D9E2EC;
    font-size: 0.96rem;
    font-weight: 600;
    letter-spacing: -0.01em;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover {
    transform: translateX(2px);
    border-color: rgba(88, 166, 255, 0.32);
    background: linear-gradient(135deg, rgba(88, 166, 255, 0.14), rgba(63, 185, 80, 0.08), rgba(210, 153, 34, 0.1));
    box-shadow: 0 10px 24px rgba(0, 0, 0, 0.22);
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] {
    border-color: rgba(255, 255, 255, 0.1);
    background: linear-gradient(135deg, rgba(88, 166, 255, 0.28), rgba(39, 106, 196, 0.22) 45%, rgba(63, 185, 80, 0.18));
    box-shadow: 0 14px 34px rgba(2, 8, 23, 0.34);
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"]::after {
    content: "Live";
    position: absolute;
    top: 50%;
    right: 12px;
    transform: translateY(-50%);
    padding: 0.18rem 0.45rem;
    border-radius: 999px;
    background: rgba(255, 255, 255, 0.12);
    color: #F8FBFF;
    font-size: 0.65rem;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.08em;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] p {
    color: #FFFFFF;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] svg {
    color: #8B949E;
}

section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"][aria-current="page"] svg,
section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"]:hover svg {
    color: #FFFFFF;
}

/* ── Metric Cards ────────────────────────────────────────── */
div[data-testid="stMetric"] {
    background: linear-gradient(135deg, #161B22 0%, #1C2333 100%);
    border: 1px solid #30363D;
    border-radius: 12px;
    padding: 1rem 1.25rem;
    transition: all 0.2s ease;
}

div[data-testid="stMetric"]:hover {
    border-color: #D4AF3760;
    box-shadow: 0 4px 12px rgba(212, 175, 55, 0.08);
}

div[data-testid="stMetric"] label {
    color: #8B949E !important;
    font-size: 0.8rem;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.05em;
}

div[data-testid="stMetric"] [data-testid="stMetricValue"] {
    color: #EAEAEA;
    font-weight: 700;
    font-size: 1.75rem;
}

div[data-testid="stMetric"] [data-testid="stMetricDelta"] {
    font-size: 0.8rem;
}

/* ── Tabs ────────────────────────────────────────────────── */
.stTabs [data-baseweb="tab-list"] {
    gap: 0;
    background: #161B22;
    border-radius: 10px;
    padding: 4px;
    border: 1px solid #30363D;
}

.stTabs [data-baseweb="tab"] {
    border-radius: 8px;
    padding: 0.6rem 1.2rem;
    font-weight: 500;
    color: #8B949E;
    border: none;
}

.stTabs [aria-selected="true"] {
    background: #D4AF37 !important;
    color: #0D1117 !important;
    font-weight: 600;
}

/* ── Expanders ───────────────────────────────────────────── */
details[data-testid="stExpander"] {
    background: #161B22;
    border: 1px solid #30363D;
    border-radius: 10px;
    margin-bottom: 0.5rem;
}

details[data-testid="stExpander"]:hover {
    border-color: #D4AF3740;
}

details[data-testid="stExpander"] summary {
    font-weight: 500;
}

/* ── Buttons ─────────────────────────────────────────────── */
.stButton > button[kind="primary"],
.stFormSubmitButton > button[kind="primary"] {
    background: linear-gradient(135deg, #D4AF37 0%, #B8960C 100%);
    color: #0D1117;
    border: none;
    font-weight: 600;
    border-radius: 8px;
    padding: 0.5rem 1.5rem;
    transition: all 0.2s ease;
}

.stButton > button[kind="primary"]:hover,
.stFormSubmitButton > button[kind="primary"]:hover {
    background: linear-gradient(135deg, #F0D878 0%, #D4AF37 100%);
    box-shadow: 0 4px 12px rgba(212, 175, 55, 0.3);
}

.stButton > button:not([kind="primary"]) {
    border: 1px solid #30363D;
    border-radius: 8px;
    color: #EAEAEA;
    transition: all 0.2s ease;
}

.stButton > button:not([kind="primary"]):hover {
    border-color: #D4AF37;
    color: #D4AF37;
}

/* ── Forms ────────────────────────────────────────────────── */
[data-testid="stForm"] {
    background: #161B22;
    border: 1px solid #30363D;
    border-radius: 12px;
    padding: 1.5rem;
}

/* ── DataFrames / Tables ─────────────────────────────────── */
.stDataFrame {
    border-radius: 10px;
    overflow: hidden;
}

div[data-testid="stPlotlyChart"] {
    background: #0F141D;
    border: 1px solid #30363D;
    border-radius: 12px;
    padding: 0.35rem;
}

/* ── Alerts ──────────────────────────────────────────────── */
.stAlert {
    border-radius: 10px;
    border-left-width: 4px;
}

/* ── Dividers ────────────────────────────────────────────── */
hr {
    border-color: #30363D;
    opacity: 0.5;
}

/* ── Progress bars ───────────────────────────────────────── */
.stProgress > div > div {
    background: linear-gradient(90deg, #D4AF37, #F0D878);
    border-radius: 10px;
}

/* ── Selectbox / Inputs ──────────────────────────────────── */
.stSelectbox > div > div,
.stMultiSelect > div > div,
.stTextInput > div > div > input,
.stTextArea > div > div > textarea,
.stNumberInput > div > div > input {
    border-radius: 8px;
    border-color: #30363D;
}

.stSelectbox > div > div:focus-within,
.stTextInput > div > div > input:focus,
.stTextArea > div > div > textarea:focus,
.stNumberInput > div > div > input:focus {
    border-color: #D4AF37;
    box-shadow: 0 0 0 1px #D4AF3740;
}

/* ── Radio buttons ───────────────────────────────────────── */
.stRadio > div {
    gap: 0.5rem;
}

/* ── Mobile & Tablet Breakpoints ────────────────────────── */
@media (max-width: 900px) {
    .block-container {
        padding-top: 1rem;
        padding-bottom: 1rem;
        padding-left: 1rem;
        padding-right: 1rem;
    }

    .cr-page-header {
        padding: 1.2rem 1rem;
        margin-bottom: 1rem;
    }

    .cr-page-header h1 {
        font-size: 1.35rem;
    }

    .cr-page-subtitle {
        font-size: 0.85rem;
    }

    .stTabs [data-baseweb="tab"] {
        padding: 0.45rem 0.6rem;
        font-size: 0.82rem;
    }

    div[data-testid="stMetric"] {
        padding: 0.75rem 0.8rem;
    }

    div[data-testid="stMetric"] [data-testid="stMetricValue"] {
        font-size: 1.35rem;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarNav"]::before {
        font-size: 0.68rem;
        letter-spacing: 0.08em;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] {
        padding: 0.7rem 0.8rem 0.7rem 0.95rem;
    }

    section[data-testid="stSidebar"] [data-testid="stSidebarNavLink"] p {
        font-size: 0.9rem;
    }
}

@media (max-width: 640px) {
    .cr-page-header {
        border-radius: 12px;
    }

    .cr-page-header h1 {
        font-size: 1.2rem;
    }

    p, li, .stMarkdown {
        font-size: 0.9rem;
    }
}
</style>
"""


def _configure_plotly_theme():
    """Set a high-contrast Plotly template consistent with the platform theme."""
    template = go.layout.Template()
    template.layout = go.Layout(
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(color="#EAEAEA", family="Inter, Segoe UI, sans-serif"),
        colorway=["#D4AF37", "#58A6FF", "#3FB950", "#D29922", "#F85149", "#A371F7"],
        hoverlabel=dict(bgcolor="#161B22", bordercolor="#30363D", font=dict(color="#EAEAEA")),
        xaxis=dict(gridcolor="#2B3342", linecolor="#30363D", zerolinecolor="#2B3342"),
        yaxis=dict(gridcolor="#2B3342", linecolor="#30363D", zerolinecolor="#2B3342"),
    )
    pio.templates["cyberresilient_dark"] = template
    pio.templates.default = "cyberresilient_dark"


def inject_platform_css():
    """Inject the professional platform CSS. Call once at the top of every page."""
    st.markdown(_PLATFORM_CSS, unsafe_allow_html=True)
    _configure_plotly_theme()


# ── Reusable UI Components ────────────────────────────────────

def page_header(title: str, subtitle: str = "", icon: str = "🛡️"):
    """Render a branded page header with gradient background."""
    inject_platform_css()
    header_html = f"""
    <div class="cr-page-header">
        <div style="
            position: absolute; top: 0; left: 0; right: 0; height: 3px;
            background: linear-gradient(90deg, #D4AF37, #F0D878, #D4AF37);
        "></div>
        <div style="display: flex; align-items: center; gap: 1rem;">
            <span style="font-size: 2.5rem;">{icon}</span>
            <div>
                <h1>{title}</h1>
                {"<p class='cr-page-subtitle'>" + subtitle + "</p>" if subtitle else ""}
            </div>
        </div>
    </div>
    """
    st.markdown(header_html, unsafe_allow_html=True)


def kpi_card(label: str, value: str, delta: str = "", color: str = "#D4AF37"):
    """Render a styled KPI value as an HTML card."""
    delta_html = ""
    if delta:
        delta_html = f"<div style='color: #8B949E; font-size: 0.8rem; margin-top: 0.25rem;'>{delta}</div>"

    return f"""
    <div style="
        background: linear-gradient(135deg, #161B22 0%, #1C2333 100%);
        border: 1px solid #30363D;
        border-radius: 12px;
        padding: 1.25rem 1.5rem;
        text-align: center;
        transition: all 0.2s ease;
    ">
        <div style="color: #8B949E; font-size: 0.75rem; text-transform: uppercase;
                    letter-spacing: 0.08em; font-weight: 500; margin-bottom: 0.5rem;">
            {label}
        </div>
        <div style="color: {color}; font-size: 2rem; font-weight: 700; line-height: 1;">
            {value}
        </div>
        {delta_html}
    </div>
    """


def section_header(title: str, description: str = ""):
    """Render a section divider with title."""
    desc_html = f"<span style='color: #8B949E; font-weight: 400; font-size: 0.9rem; margin-left: 0.75rem;'>{description}</span>" if description else ""
    st.markdown(
        f"<div style='border-bottom: 1px solid #30363D; padding-bottom: 0.5rem; margin: 1.5rem 0 1rem 0;'>"
        f"<span style='color: #EAEAEA; font-size: 1.15rem; font-weight: 600;'>{title}</span>"
        f"{desc_html}</div>",
        unsafe_allow_html=True,
    )


def status_badge(text: str, variant: str = "info") -> str:
    """Return an HTML span badge. variant: success/warning/error/info/gold."""
    palette = {
        "success": ("#3FB950", "#3FB95020"),
        "warning": ("#D29922", "#D2992220"),
        "error":   ("#F85149", "#F8514920"),
        "info":    ("#58A6FF", "#58A6FF20"),
        "gold":    ("#D4AF37", "#D4AF3720"),
    }
    fg, bg = palette.get(variant, palette["info"])
    return (
        f"<span style='background:{bg}; color:{fg}; padding: 0.2rem 0.65rem; "
        f"border-radius: 20px; font-size: 0.78rem; font-weight: 600; "
        f"border: 1px solid {fg}30;'>{text}</span>"
    )


def card_container(content_html: str, accent: bool = False):
    """Wrap HTML content in a styled card container."""
    border_style = "border-color: #D4AF3740;" if accent else "border-color: #30363D;"
    st.markdown(
        f"""<div style="
            background: #161B22;
            border: 1px solid; {border_style}
            border-radius: 12px;
            padding: 1.5rem;
            margin-bottom: 1rem;
        ">{content_html}</div>""",
        unsafe_allow_html=True,
    )


def footer():
    """Render a professional footer."""
    st.markdown(
        """<div style="
            text-align: center; padding: 2rem 0 1rem 0;
            border-top: 1px solid #30363D; margin-top: 2rem;
        ">
            <span style="color: #6E7681; font-size: 0.8rem;">
                CyberResilient GRC Platform &mdash; Governance, Risk & Compliance
            </span>
        </div>""",
        unsafe_allow_html=True,
    )

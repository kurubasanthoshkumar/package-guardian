"""Package Guardian: a supply-chain scanner for Python requirements files.

Run with:  streamlit run app.py
"""
from __future__ import annotations

import html
import json
import re
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from difflib import SequenceMatcher

import pandas as pd
import streamlit as st

st.set_page_config(page_title="Package Guardian", page_icon="🛡️", layout="wide")


# ───────────────────────────── Reference data ─────────────────────────────
def normalize(name: str) -> str:
    """PEP 503 normalisation: 'Typing_Extensions' -> 'typing-extensions'."""
    return re.sub(r"[-_.]+", "-", name).lower()


TRUSTED = {normalize(n) for n in """
    requests urllib3 numpy pandas flask django colorama setuptools wheel pip boto3
    botocore pytest scipy matplotlib pillow cryptography pyyaml jinja2 sqlalchemy
    certifi idna charset-normalizer click six python-dateutil packaging rich
    streamlit typing-extensions
""".split()}

KNOWN_TYPOSQUATS = {
    "reqeusts": "requests", "colorma": "colorama", "flak": "flask",
    "numpyy": "numpy", "urllib4": "urllib3",
}

SAMPLE = """# Legitimate packages
requests==2.31.0
colorama==0.4.6
flask==3.0.0
rich==13.7.0

# Known and suspected typosquats
reqeusts==2.31.0
colorma==0.4.6
djangoo==4.2.7

# Unpinned entries
urllib3>=1.26.0
numpy

# Duplicate entry
requests==2.31.0

# Not a package
--index-url https://pypi.org/simple
$$invalid_pkg@@
"""

RISK_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
RISK_ICON = {"HIGH": "🔴", "MEDIUM": "🟠", "LOW": "🟢"}


# ───────────────────────────── Scanning engine ─────────────────────────────
OPS = r"(?:===|==|~=|!=|>=|<=|>|<)"
VER = r"[A-Za-z0-9.*+!_-]+"
LINE_RE = re.compile(
    r"^(?P<name>[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?)"
    r"(?:\s*\[[A-Za-z0-9,._\s-]*\])?"
    rf"\s*(?P<spec>(?:{OPS}\s*{VER}\s*,?\s*)*)$"
)
CLAUSE_RE = re.compile(rf"({OPS})\s*({VER})")


@dataclass
class Finding:
    line: int
    name: str
    constraint: str
    pinned: bool
    risk: str
    finding: str
    action: str
    suggestion: str = ""


def parse_requirements(text: str):
    """Return (records, skipped). Skipped items are (line_no, content, reason)."""
    records, skipped = [], []
    for no, raw in enumerate(text.splitlines(), start=1):
        line = raw.split(" #")[0].split(";")[0].strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("-"):
            skipped.append((no, raw.strip()[:200], "pip option, not a package"))
            continue
        match = LINE_RE.match(line) if len(line) <= 200 else None
        if not match:
            skipped.append((no, raw.strip()[:200], "Invalid requirement syntax"))
            continue
        clauses = CLAUSE_RE.findall(match["spec"])
        records.append({
            "line": no,
            "name": normalize(match["name"]),
            "constraint": "".join(match["spec"].split()).rstrip(",") or "none",
            "pinned": len(clauses) == 1 and clauses[0][0] in ("==", "===") and "*" not in clauses[0][1],
        })
    return records, skipped


def closest_trusted(name: str, cutoff: float):
    """Best lookalike among trusted packages, or (None, 0.0)."""
    if len(name) < 5 or name in TRUSTED:
        return None, 0.0
    best, score = None, 0.0
    for trusted in TRUSTED:
        ratio = SequenceMatcher(None, name, trusted).ratio()
        if ratio > score:
            best, score = trusted, ratio
    return (best, score) if score >= cutoff else (None, 0.0)


def classify(name: str, pinned: bool, declarations: int, cutoff: float):
    """Return (risk, finding, recommended action, suggested replacement)."""
    if name in KNOWN_TYPOSQUATS:
        real = KNOWN_TYPOSQUATS[name]
        return "HIGH", "Known typosquat", f"Replace with '{real}' and check how this entry got here.", real
    match, score = closest_trusted(name, cutoff)
    if match:
        return "HIGH", f"Possible lookalike of '{match}' ({score:.0%} similar)", \
            f"Check the name on pypi.org. If it is a typo, use '{match}'.", match
    if declarations > 1:
        return "MEDIUM", f"Declared {declarations} times", "Keep one entry per package.", ""
    if not pinned:
        return "MEDIUM", "Version not pinned", "Pin an exact version with '=='.", ""
    if name in TRUSTED:
        return "LOW", "Trusted and pinned", "No action needed.", ""
    return "MEDIUM", "Unverified package", "Confirm the publisher and project history on PyPI.", ""


def analyze(records, cutoff: float):
    counts = {}
    for r in records:
        counts[r["name"]] = counts.get(r["name"], 0) + 1
    findings = []
    for r in records:
        risk, finding, action, suggestion = classify(r["name"], r["pinned"], counts[r["name"]], cutoff)
        findings.append(Finding(r["line"], r["name"], r["constraint"], r["pinned"], risk, finding, action, suggestion))
    return findings


def build_hardened(findings) -> str:
    """A cleaned requirements file: lookalikes replaced, duplicates removed."""
    lines, seen = [], set()
    for f in sorted(findings, key=lambda f: f.line):
        name = f.suggestion or f.name
        if name in seen:
            continue
        seen.add(name)
        spec = "" if f.constraint == "none" else f.constraint
        note = (f"replaced '{f.name}' (suspected typosquat)" if f.suggestion
                else "TODO: pin an exact version with ==" if not f.pinned else "")
        lines.append(f"{name}{spec}" + (f"  # {note}" if note else ""))
    return "\n".join(lines) + "\n"


def to_frame(findings) -> pd.DataFrame:
    return pd.DataFrame([{
        "Line": f.line, "Package": f.name, "Constraint": f.constraint,
        "Risk": f"{RISK_ICON[f.risk]} {f.risk.title()}",
        "Finding": f.finding, "Recommended action": f.action,
    } for f in findings])


# ───────────────────────────── Presentation ─────────────────────────────
STYLE = """
<style>
@import url('https://fonts.googleapis.com/css2?family=IBM+Plex+Sans:wght@400;500;600&display=swap');
.block-container { padding-top: 2.5rem; max-width: 1180px; }
footer { visibility: hidden; }
.pg-title, .pg-sub, .pg-verdict, .pg-ledger { font-family: 'IBM Plex Sans', system-ui, sans-serif; }
.pg-title { font-size: 2.2rem; font-weight: 600; letter-spacing: -0.015em; line-height: 1.15; margin: 0; }
.pg-sub { opacity: .72; font-size: 1.02rem; max-width: 62ch; margin: .45rem 0 1.8rem; }
.pg-verdict { border: 1px solid rgba(128,128,128,.3); border-left: 7px solid var(--tone);
  border-radius: 6px; padding: 1.2rem 1.5rem 1.3rem; }
.pg-vt { color: var(--tone); font-size: 1.75rem; font-weight: 600; letter-spacing: -0.01em; line-height: 1.2; }
.pg-vb { margin-top: .35rem; max-width: 80ch; line-height: 1.5; }
.tone-high { --tone: #c2342b; } .tone-medium { --tone: #b7791f; } .tone-low { --tone: #2f855a; }
.pg-bar { display: flex; height: 8px; border-radius: 4px; overflow: hidden;
  background: rgba(128,128,128,.2); margin-top: 1.1rem; }
.pg-bar span { display: block; height: 100%; }
.seg-high { background: #c2342b; } .seg-medium { background: #b7791f; } .seg-low { background: #2f855a; }
.pg-ledger { display: flex; flex-wrap: wrap; margin: 1.4rem 0 1.2rem;
  border-top: 1px solid rgba(128,128,128,.3); border-bottom: 1px solid rgba(128,128,128,.3); }
.pg-ledger > div { flex: 1 1 140px; padding: 1rem 1.3rem; border-left: 1px solid rgba(128,128,128,.3); }
.pg-ledger > div:first-child { border-left: 0; padding-left: 0; }
.pg-num { font-size: 2.1rem; font-weight: 600; line-height: 1.1; }
.pg-lab { opacity: .7; font-size: .92rem; margin-top: .2rem; }
.num-high { color: #c2342b; } .num-medium { color: #b7791f; } .num-low { color: #2f855a; }
</style>
"""


def h(value) -> str:
    return html.escape(str(value))


def table(df: pd.DataFrame) -> None:
    try:
        st.dataframe(df, hide_index=True, width="stretch")
    except Exception:  # older Streamlit releases
        st.dataframe(df, hide_index=True, use_container_width=True)


def load_sample() -> None:
    st.session_state["deps_text"] = SAMPLE


st.markdown(STYLE, unsafe_allow_html=True)
st.markdown(
    '<div class="pg-title">Package Guardian</div>'
    '<div class="pg-sub">Scan a Python requirements file for typosquatted, duplicated and '
    'unpinned packages before they reach your build.</div>',
    unsafe_allow_html=True,
)

with st.sidebar:
    st.subheader("Scan settings")
    source = st.radio("Input", ["Paste text", "Upload requirements.txt"])
    text = ""
    if source == "Paste text":
        st.session_state.setdefault("deps_text", SAMPLE)
        st.text_area("Dependencies, one per line", key="deps_text", height=280)
        st.button("Reset to sample data", on_click=load_sample)
        text = st.session_state["deps_text"]
    else:
        upload = st.file_uploader("Choose a file", type=["txt"])
        if upload is not None and upload.size > 1_000_000:
            st.error("This file is larger than 1 MB. Upload a smaller requirements file.")
        elif upload is not None:
            text = upload.getvalue().decode("utf-8", errors="replace")
    st.divider()
    cutoff = st.slider("Lookalike sensitivity", 0.75, 0.95, 0.85, 0.01,
                       help="Minimum name similarity to a trusted package before it is flagged. Lower values catch more typos and raise more false alarms.")
    policy = st.radio("Block the build on", ["High findings", "High and medium findings"])

if not text.strip():
    st.info("Paste dependencies or upload a requirements.txt in the sidebar to start a scan.")
    st.stop()

records, skipped = parse_requirements(text)
if not records:
    st.warning("No valid requirements found. Each line should look like `package==1.2.3`.")
    if skipped:
        table(pd.DataFrame(skipped, columns=["Line", "Content", "Reason"]))
    st.stop()

findings = analyze(records, cutoff)
counts = {k: sum(f.risk == k for f in findings) for k in RISK_ORDER}
total = len(findings)
pinned_pct = round(100 * sum(f.pinned for f in findings) / total)

# Verdict
if counts["HIGH"]:
    names = ", ".join(sorted({f.name for f in findings if f.risk == "HIGH"}))
    tone, title = "high", "Build blocked"
    body = f"Suspected typosquats: {names}. Do not install until each one is verified."
elif counts["MEDIUM"] and policy.startswith("High and"):
    tone, title = "high", "Build blocked by policy"
    body = f"{counts['MEDIUM']} medium-risk entries must be resolved before this file can pass."
elif counts["MEDIUM"]:
    tone, title = "medium", "Review required"
    body = f"{counts['MEDIUM']} medium-risk entries: unpinned, duplicated or unverified packages."
else:
    tone, title = "low", "Passed"
    body = "Every package is trusted and pinned to an exact version."

segments = "".join(
    f'<span class="seg-{k.lower()}" style="width:{counts[k] / total * 100:.1f}%"></span>'
    for k in RISK_ORDER if counts[k]
)
st.markdown(
    f'<div class="pg-verdict tone-{tone}"><div class="pg-vt">{h(title)}</div>'
    f'<div class="pg-vb">{h(body)}</div>'
    f'<div class="pg-bar" role="img" aria-label="Share of dependencies by risk level">{segments}</div></div>',
    unsafe_allow_html=True,
)

ledger = [
    (total, "Dependencies scanned", ""),
    (counts["HIGH"], "High risk", "num-high" if counts["HIGH"] else ""),
    (counts["MEDIUM"], "Medium risk", "num-medium" if counts["MEDIUM"] else ""),
    (counts["LOW"], "Low risk", "num-low" if counts["LOW"] else ""),
    (f"{pinned_pct}%", "Pinned to an exact version", ""),
]
st.markdown(
    '<div class="pg-ledger">' + "".join(
        f'<div><div class="pg-num {cls}">{h(v)}</div><div class="pg-lab">{h(lab)}</div></div>'
        for v, lab, cls in ledger) + "</div>",
    unsafe_allow_html=True,
)

tab_findings, tab_fix, tab_export = st.tabs(["Findings", "Remediation", "Export"])

with tab_findings:
    levels = st.multiselect("Show risk levels", ["High", "Medium", "Low"], default=["High", "Medium", "Low"])
    ranked = sorted((f for f in findings if f.risk.title() in levels), key=lambda f: (RISK_ORDER[f.risk], f.line))
    if ranked:
        table(to_frame(ranked))
    else:
        st.caption("No findings match the selected risk levels.")
    if skipped:
        with st.expander(f"{len(skipped)} line(s) skipped"):
            table(pd.DataFrame(skipped, columns=["Line", "Content", "Reason"]))

with tab_fix:
    replacements = [f for f in findings if f.suggestion]
    unpinned = sorted({f.name for f in findings if not f.pinned and not f.suggestion})
    if replacements:
        st.markdown("**Replace before installing**")
        for f in replacements:
            st.markdown(f"- `{f.name}` → `{f.suggestion}` (line {f.line}): {f.finding}")
    if unpinned:
        st.markdown("**Pin to an exact version**")
        st.markdown(", ".join(f"`{n}`" for n in unpinned))
    if not replacements and not unpinned and counts["MEDIUM"] == 0:
        st.success("Nothing to fix. Every entry is trusted and pinned.")
    hardened = build_hardened(findings)
    st.markdown("**Hardened requirements.txt**")
    st.caption("Lookalikes replaced, duplicates removed and unpinned entries marked for review.")
    st.code(hardened, language="text")
    st.download_button("Download requirements.hardened.txt", hardened, "requirements.hardened.txt", "text/plain")

with tab_export:
    report = {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "verdict": title,
        "policy": f"Block on: {policy.lower()}",
        "lookalike_sensitivity": cutoff,
        "summary": {"total": total, **{k.lower(): v for k, v in counts.items()}, "pinned_percent": pinned_pct},
        "findings": [asdict(f) for f in sorted(findings, key=lambda f: f.line)],
        "skipped_lines": [{"line": n, "content": c, "reason": r} for n, c, r in skipped],
    }
    left, right = st.columns(2)
    left.download_button("Download findings (CSV)", to_frame(sorted(findings, key=lambda f: f.line)).to_csv(index=False),
                         "package_guardian_findings.csv", "text/csv")
    right.download_button("Download full report (JSON)", json.dumps(report, indent=2),
                          "package_guardian_report.json", "application/json")
    st.json(report, expanded=False)

st.caption("Lookalike detection compares names with a built-in list of popular packages. "
           "Treat a match as a lead to verify on PyPI, not as proof of malice.")
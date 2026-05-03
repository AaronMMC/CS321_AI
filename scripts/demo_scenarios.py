#!/usr/bin/env python3
"""
scripts/demo_scenarios.py
─────────────────────────
Live demonstration script for the Email Security Gateway.

Runs all four demo scenarios against the running FastAPI service and prints
a formatted, colour-coded report to the terminal.

USAGE
─────
# 1. Train the model (only needed once)
python scripts/train_model.py

# 2. Start the API
python -m uvicorn src.api.main:app --host 0.0.0.0 --port 8000 --reload

# 3. (Optional) Start the dashboard in another terminal
python -m streamlit run src/dashboard/app.py

# 4. Run the demo
python scripts/demo_scenarios.py

# Point at a different API host
python scripts/demo_scenarios.py --api http://localhost:8000 --pause 2
"""

import argparse
import sys
import time
from typing import Any, Dict, List, Optional

try:
    import requests
except ImportError:
    print("ERROR: 'requests' not installed. Run: pip install requests")
    sys.exit(1)

# ── ANSI colour codes ─────────────────────────────────────────────────────────
_RESET  = "\033[0m"
_BOLD   = "\033[1m"
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_GREY   = "\033[90m"
_WHITE  = "\033[97m"


def _c(text: str, *codes: str) -> str:
    if not sys.stdout.isatty():
        return text
    return "".join(codes) + text + _RESET


# ── Scenarios ─────────────────────────────────────────────────────────────────

SCENARIOS: List[Dict[str, Any]] = [
    {
        "name":   "Legitimate Email — Clean Delivery",
        "number": 1,
        "payload": {
            "subject":    "Leave Request Approved — May 15–20",
            "body": (
                "Hello Maria,\n\n"
                "Your leave request for May 15–20, 2025 has been approved.\n\n"
                "Remaining leave credits: 12 days.\n"
                "Please ensure your tasks are handed over before your leave.\n\n"
                "Best regards,\nHR Department\nhr@deped.gov.ph"
            ),
            "from_email": "hr@deped.gov.ph",
        },
        "expected_action": "delivered",
        "description": (
            "A routine HR email from an authentic @deped.gov.ph address.\n"
            "The recipient should receive it with zero modification."
        ),
    },
    {
        "name":   "Phishing Email — Warning Banner Injected",
        "number": 2,
        "payload": {
            "subject":    "URGENT: Your GCash Account Will Be Suspended",
            "body": (
                "Dear Customer,\n\n"
                "Your GCash account has been flagged for unusual activity.\n"
                "To avoid permanent suspension, please verify your account immediately.\n\n"
                "Click here to verify: http://bit.ly/gcash-verify-urgent\n\n"
                "Failure to verify within 24 hours will result in account closure.\n\n"
                "GCash Support Team\nsupport@gcash-security.net"
            ),
            "from_email": "support@gcash-verify.net",
        },
        "expected_action": "warned",
        "description": (
            "Classic GCash impersonation with a bit.ly link.\n"
            "Gateway injects a [WARNING] banner — email is delivered\n"
            "but the recipient is clearly warned not to click anything."
        ),
    },
    {
        "name":   "Critical Threat — Email Quarantined",
        "number": 3,
        "payload": {
            "subject":    "DICT: Email Verification Required — Immediate Action",
            "body": (
                "ATTENTION DICT EMAIL USER,\n\n"
                "Your DICT email account has been selected for mandatory verification.\n"
                "Click the link below or your account will be permanently deactivated.\n\n"
                "http://bit.ly/dict-verify-now\n\n"
                "Department of Information and Communications Technology\n"
                "admin@dict-verify.com"
            ),
            "from_email": "admin@dict-verify.com",
        },
        "expected_action": "quarantined",
        "description": (
            "DICT government domain impersonation — very high threat score.\n"
            "Gateway quarantines the email: it NEVER reaches the inbox."
        ),
    },
    {
        "name":   "Campaign Attack — Multiple Recipients Targeted",
        "number": 4,
        "payload": {
            "subject":    "HR: Update Your Payroll Information",
            "body": (
                "Dear Employee,\n\n"
                "We are updating our payroll system. Please verify your information:\n\n"
                "http://bit.ly/payroll-update\n\n"
                "Failure to update may delay your next salary.\n\n"
                "HR Department\nhr@company-payroll.com"
            ),
            "from_email": "hr@company-payroll.com",
        },
        "expected_action": "warned",
        "description": (
            "Payroll-themed social engineering targeting multiple recipients.\n"
            "The campaign detector fires after 3+ emails from the same domain,\n"
            "boosting the score and triggering an admin alert."
        ),
    },
]

# ── Display helpers ───────────────────────────────────────────────────────────

_ACTION_COLOUR = {
    "delivered":   _GREEN,
    "warned":      _YELLOW,
    "quarantined": _RED,
}
_LEVEL_COLOUR = {
    "SAFE":     _GREEN,
    "LOW":      _GREY,
    "MEDIUM":   _YELLOW,
    "HIGH":     _YELLOW,
    "CRITICAL": _RED,
}


def _divider(char: str = "─", width: int = 68) -> None:
    print(_c(char * width, _GREY))


def _header(text: str) -> None:
    _divider("═")
    print(_c(f"  {text}", _BOLD, _WHITE))
    _divider("═")


def _scenario_header(sc: Dict) -> None:
    _divider()
    print(_c(f"\n  SCENARIO {sc['number']}  —  {sc['name']}\n", _BOLD, _CYAN))
    for line in sc["description"].splitlines():
        print(_c(f"  {line}", _GREY))
    print()


def _email_preview(payload: Dict) -> None:
    print(_c("  Email being sent through the gateway:", _GREY))
    print(f"    From    : {_c(payload['from_email'], _WHITE)}")
    print(f"    Subject : {_c(payload['subject'], _WHITE)}")
    preview = payload["body"].replace("\n", " ")[:100]
    print(f"    Body    : {_c(preview + '…', _GREY)}")
    print()


def _action_from_score(score: float) -> str:
    if score >= 0.80: return "quarantined"
    if score >= 0.40: return "warned"
    return "delivered"


def _print_result(result: Dict) -> None:
    score      = result.get("threat_score", 0.0)
    level      = result.get("risk_level", "UNKNOWN")
    action     = _action_from_score(score)
    level_col  = _LEVEL_COLOUR.get(level, _WHITE)
    action_col = _ACTION_COLOUR.get(action, _WHITE)

    print(_c("  RESULT", _BOLD))
    print(f"    Threat score : {_c(f'{score:.0%}', level_col, _BOLD)}")
    print(f"    Risk level   : {_c(level, level_col, _BOLD)}")
    print(f"    Action taken : {_c(action.upper(), action_col, _BOLD)}")
    if result.get("alert_sent"):
        print(f"    Email alert  : {_c('Sent ✓', _GREEN)}")
    print()

    print(_c("  CLIENT VIEW", _BOLD))
    if action == "quarantined":
        print(_c("    Email never arrived in inbox — recipient sees nothing.", _GREEN))
    elif action == "warned":
        print(_c(
            "    Email delivered with a [WARNING] banner injected at the top.\n"
            "    Subject is prefixed with [SUSPICIOUS] or [WARNING].",
            _YELLOW,
        ))
    else:
        print(_c("    Email delivered cleanly — no visible difference.", _GREEN))

    print()
    print(_c("  ADMIN VIEW — Explanations", _BOLD))
    for exp in result.get("explanations", [])[:5]:
        print(f"    • {_c(exp, _GREY)}")

    # Auth block
    auth = result.get("auth")
    if auth:
        spf   = auth.get("spf",   "—")
        dkim  = auth.get("dkim",  "—")
        dmarc = auth.get("dmarc", "—")
        spf_col  = _GREEN if "Pass" in str(spf)  else _RED
        dkim_col = _GREEN if "Pass" in str(dkim) else _RED
        print(
            f"\n    Auth  →  SPF: {_c(str(spf)[:30], spf_col)}  "
            f"DKIM: {_c(str(dkim)[:30], dkim_col)}  "
            f"DMARC: {_c(str(dmarc)[:40], _GREY)}"
        )

    # Intel block
    intel = result.get("intel")
    if intel:
        vt  = intel.get("virustotal_flags",  "—")
        age = intel.get("domain_age_label",  "—")
        gsb = intel.get("google_safe_browsing", "—")
        gsb_col = _RED if "Threat" in str(gsb) else _GREEN
        print(
            f"    Intel →  VirusTotal: {_c(str(vt)[:40], _GREY)}  "
            f"Domain age: {_c(str(age), _GREY)}  "
            f"Google SB: {_c(str(gsb), gsb_col)}"
        )
    print()


# ── Main runner ───────────────────────────────────────────────────────────────

def run_demo(api_base: str, pause_seconds: float) -> None:
    _header("EMAIL SECURITY GATEWAY — LIVE DEMO")
    print(_c(
        f"\n  API endpoint : {api_base}\n"
        f"  Dashboard    : http://localhost:8501\n",
        _GREY,
    ))

    # Verify API is up
    try:
        r    = requests.get(f"{api_base.rstrip('/')}/", timeout=5)
        info = r.json()
        model_status = (
            _c("loaded ✓", _GREEN) if info.get("model_loaded")
            else _c("NOT loaded ✗  — run: python scripts/train_model.py", _RED)
        )
        alert_status = (
            _c("Gmail alerts active ✓", _GREEN) if info.get("email_alerts")
            else _c("Gmail alerts inactive (set GMAIL_ADDRESS in .env)", _YELLOW)
        )
        print(f"  Gateway  : {_c('operational', _GREEN)}")
        print(f"  Model    : {model_status}")
        print(f"  Alerting : {alert_status}\n")
    except Exception as exc:
        print(_c(
            f"\n  ERROR: Cannot reach API at {api_base}\n"
            f"  Start it with:  python -m uvicorn src.api.main:app --port 8000\n"
            f"  ({exc})\n",
            _RED,
        ))
        sys.exit(1)

    results_summary: List[Dict] = []

    # ── Run each scenario ─────────────────────────────────────────────────────
    for sc in SCENARIOS:
        _scenario_header(sc)
        _email_preview(sc["payload"])

        try:
            resp = requests.post(
                f"{api_base.rstrip('/')}/api/v1/check-email",
                json=sc["payload"],
                timeout=20,
            )
            resp.raise_for_status()
            result = resp.json()
        except requests.exceptions.Timeout:
            print(_c("  ERROR: Request timed out (model may still be loading).\n", _RED))
            continue
        except Exception as exc:
            print(_c(f"  ERROR: {exc}\n", _RED))
            continue

        _print_result(result)
        results_summary.append({
            "scenario": sc["name"],
            "score":    result.get("threat_score", 0.0),
            "level":    result.get("risk_level", "?"),
            "action":   _action_from_score(result.get("threat_score", 0.0)),
        })

        if pause_seconds > 0 and sc["number"] < len(SCENARIOS):
            print(_c(f"  (pausing {pause_seconds:.0f}s …)\n", _GREY))
            time.sleep(pause_seconds)

    # ── Summary table — printed ONCE after all scenarios ──────────────────────
    _header("DEMO SUMMARY")
    print(f"  {'#':<3}  {'Scenario':<42}  {'Score':>6}  {'Level':<10}  {'Action'}")
    _divider()
    for i, row in enumerate(results_summary, 1):
        level_col  = _LEVEL_COLOUR.get(row["level"], _WHITE)
        action_col = _ACTION_COLOUR.get(row["action"], _WHITE)
        score_str  = f"{row['score']:.0%}"
        level_str  = row["level"]
        action_str = row["action"].upper()
        print(
            f"  {i:<3}  {row['scenario'][:42]:<42}  "
            f"{_c(score_str, level_col, _BOLD):>6}  "
            f"{_c(level_str, level_col):<10}  "
            f"{_c(action_str, action_col)}"
        )
    _divider()
    print(_c(
        "\n  Demo complete.\n"
        "  Open http://localhost:8501 to see the full dashboard.\n",
        _GREY,
    ))


# ── CLI ───────────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Email Security Gateway — live demo runner"
    )
    parser.add_argument(
        "--api", default="http://localhost:8000",
        help="Base URL of the FastAPI service (default: http://localhost:8000)",
    )
    parser.add_argument(
        "--pause", type=float, default=2.0, metavar="SECONDS",
        help="Pause between scenarios (default: 2 s, set 0 to skip)",
    )
    args = parser.parse_args()
    run_demo(api_base=args.api, pause_seconds=args.pause)


if __name__ == "__main__":
    main()
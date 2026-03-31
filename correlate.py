"""
correlate.py - Threat Correlation Engine
Chains related anomalies and raw events into higher-level threat incidents.
Sits between analyze.py and server.py in the pipeline.
"""

from datetime import datetime, timedelta
from collections import defaultdict
from typing import Optional


# ── Helpers ───────────────────────────────────────────────────

def _parse_time(ts: Optional[str]) -> Optional[datetime]:
    """Try to parse an ISO-ish timestamp string into a datetime."""
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ",
                "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S"):
        try:
            return datetime.strptime(ts[:19], fmt[:len(ts[:19])])
        except ValueError:
            continue
    return None


def _within(t1: Optional[datetime], t2: Optional[datetime], minutes: int) -> bool:
    """Return True if both timestamps exist and are within `minutes` of each other."""
    if t1 is None or t2 is None:
        return True   # can't disprove proximity without timestamps
    return abs((t1 - t2).total_seconds()) <= minutes * 60


def _incident(rule_id: str, title: str, severity: str,
              description: str, mitre: str, linked_events: list) -> dict:
    return {
        "rule_id":       rule_id,
        "title":         title,
        "severity":      severity,
        "description":   description,
        "mitre":         mitre,
        "linked_events": linked_events,
        "detected_at":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }


# ── Correlation Rules ─────────────────────────────────────────

def rule_brute_force_success(events: list, window_minutes: int = 10) -> list:
    """
    RULE CR-001 — Brute Force followed by Successful Logon
    Pattern : Multiple 4625 (failed logon) then 4624 (success) within window
    MITRE   : T1110 — Brute Force
    """
    incidents = []
    failures = [e for e in events if int(e.get("EventId", 0)) == 4625
                and e.get("Channel") == "Security"]
    successes = [e for e in events if int(e.get("EventId", 0)) == 4624
                 and e.get("Channel") == "Security"]

    if len(failures) < 3 or not successes:
        return incidents

    for success in successes:
        t_success = _parse_time(success.get("TimeCreated"))
        nearby_failures = [
            f for f in failures
            if _within(_parse_time(f.get("TimeCreated")), t_success, window_minutes)
        ]
        if len(nearby_failures) >= 3:
            incidents.append(_incident(
                rule_id="CR-001",
                title="Brute Force → Successful Logon",
                severity="Critical",
                description=(
                    f"{len(nearby_failures)} failed logon attempts followed by a "
                    f"successful logon within {window_minutes} minutes. "
                    "Possible credential brute-force attack."
                ),
                mitre="T1110 — Brute Force",
                linked_events=[success] + nearby_failures[:5],
            ))
            break  # one incident per success burst is enough

    return incidents


def rule_privilege_escalation(events: list, window_minutes: int = 15) -> list:
    """
    RULE CR-002 — Privilege Escalation after Failed Logons
    Pattern : 4625 spike then 4672 (special privileges assigned) within window
    MITRE   : T1068 — Exploitation for Privilege Escalation
    """
    incidents = []
    failures  = [e for e in events if int(e.get("EventId", 0)) == 4625
                 and e.get("Channel") == "Security"]
    privs     = [e for e in events if int(e.get("EventId", 0)) == 4672
                 and e.get("Channel") == "Security"]

    if len(failures) < 3 or not privs:
        return incidents

    for priv in privs:
        t_priv = _parse_time(priv.get("TimeCreated"))
        nearby = [f for f in failures
                  if _within(_parse_time(f.get("TimeCreated")), t_priv, window_minutes)]
        if len(nearby) >= 3:
            incidents.append(_incident(
                rule_id="CR-002",
                title="Privilege Escalation Indicator",
                severity="Critical",
                description=(
                    f"Special privileges assigned (4672) within {window_minutes} min "
                    f"of {len(nearby)} failed logon attempts. "
                    "Possible privilege escalation after credential attack."
                ),
                mitre="T1068 — Exploitation for Privilege Escalation",
                linked_events=[priv] + nearby[:5],
            ))
            break

    return incidents


def rule_persistence_indicator(events: list, window_minutes: int = 30) -> list:
    """
    RULE CR-003 — Persistence via New Service + New Account
    Pattern : 7045 (new service) AND 4720 (account created) within window
    MITRE   : T1543.003 — Create or Modify System Process: Windows Service
    """
    incidents = []
    new_services = [e for e in events if int(e.get("EventId", 0)) == 7045]
    new_accounts = [e for e in events if int(e.get("EventId", 0)) == 4720
                    and e.get("Channel") == "Security"]

    if not new_services or not new_accounts:
        return incidents

    for svc in new_services:
        t_svc = _parse_time(svc.get("TimeCreated"))
        nearby_accounts = [
            a for a in new_accounts
            if _within(_parse_time(a.get("TimeCreated")), t_svc, window_minutes)
        ]
        if nearby_accounts:
            incidents.append(_incident(
                rule_id="CR-003",
                title="Persistence Indicator — Service + Account Creation",
                severity="High",
                description=(
                    f"New service installed (7045) and new user account created (4720) "
                    f"within {window_minutes} minutes. "
                    "Common persistence technique."
                ),
                mitre="T1543.003 — Windows Service Persistence",
                linked_events=[svc] + nearby_accounts[:3],
            ))
            break

    return incidents


def rule_lateral_movement(events: list, threshold: int = 3) -> list:
    """
    RULE CR-004 — Lateral Movement via Repeated Explicit Credential Logons
    Pattern : 4648 (explicit creds) occurring multiple times in the window
    MITRE   : T1021 — Remote Services / Lateral Movement
    """
    incidents = []
    explicit = [e for e in events if int(e.get("EventId", 0)) == 4648
                and e.get("Channel") == "Security"]

    if len(explicit) >= threshold:
        incidents.append(_incident(
            rule_id="CR-004",
            title="Lateral Movement Indicator",
            severity="High",
            description=(
                f"{len(explicit)} explicit-credential logon events (4648) detected. "
                "May indicate lateral movement or pass-the-hash activity."
            ),
            mitre="T1021 — Remote Services",
            linked_events=explicit[:5],
        ))

    return incidents


def rule_account_manipulation(events: list, window_minutes: int = 20) -> list:
    """
    RULE CR-005 — Account Created then Immediately Locked Out
    Pattern : 4720 (create) followed by 4740 (lockout) within window
    MITRE   : T1098 — Account Manipulation
    """
    incidents = []
    created  = [e for e in events if int(e.get("EventId", 0)) == 4720]
    lockouts = [e for e in events if int(e.get("EventId", 0)) == 4740]

    if not created or not lockouts:
        return incidents

    for acct in created:
        t_create = _parse_time(acct.get("TimeCreated"))
        nearby_lockouts = [
            l for l in lockouts
            if _within(_parse_time(l.get("TimeCreated")), t_create, window_minutes)
        ]
        if nearby_lockouts:
            incidents.append(_incident(
                rule_id="CR-005",
                title="Account Created then Locked Out",
                severity="High",
                description=(
                    f"A new account was created (4720) and locked out (4740) "
                    f"within {window_minutes} minutes. "
                    "May indicate automated account abuse or failed attack tooling."
                ),
                mitre="T1098 — Account Manipulation",
                linked_events=[acct] + nearby_lockouts[:3],
            ))
            break

    return incidents


def rule_system_instability(events: list, threshold: int = 3) -> list:
    """
    RULE CR-006 — System Instability / Crash Loop
    Pattern : Multiple kernel power loss or unexpected shutdown events
    MITRE   : T1499 — Endpoint Denial of Service (impact)
    """
    incidents = []
    crash_ids = {41, 6008, 1001}
    crashes   = [e for e in events if int(e.get("EventId", 0)) in crash_ids]

    if len(crashes) >= threshold:
        incidents.append(_incident(
            rule_id="CR-006",
            title="System Instability / Crash Loop",
            severity="High",
            description=(
                f"{len(crashes)} crash/unexpected-shutdown events detected "
                f"(Event IDs: {', '.join(str(int(e.get('EventId',0))) for e in crashes[:5])}). "
                "Possible hardware failure, driver issue, or deliberate disruption."
            ),
            mitre="T1499 — Endpoint Denial of Service",
            linked_events=crashes[:5],
        ))

    return incidents


# ── Main Correlator ───────────────────────────────────────────

ALL_RULES = [
    rule_brute_force_success,
    rule_privilege_escalation,
    rule_persistence_indicator,
    rule_lateral_movement,
    rule_account_manipulation,
    rule_system_instability,
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]


def correlate(events: list, config: dict) -> list:
    """
    Run all correlation rules against the raw event list.
    Returns a deduplicated, severity-sorted list of threat incidents.
    """
    cfg = config.get("correlation", {})
    window = cfg.get("window_minutes", 15)

    incidents = []
    for rule_fn in ALL_RULES:
        try:
            # Pass window_minutes only to rules that accept it
            import inspect
            sig = inspect.signature(rule_fn)
            if "window_minutes" in sig.parameters:
                found = rule_fn(events, window_minutes=window)
            elif "threshold" in sig.parameters:
                threshold = cfg.get("thresholds", {}).get(rule_fn.__name__, 3)
                found = rule_fn(events, threshold=threshold)
            else:
                found = rule_fn(events)
            incidents.extend(found)
        except Exception as exc:
            print(f"[!] Correlation rule {rule_fn.__name__} failed: {exc}")

    # Deduplicate by rule_id (keep first occurrence)
    seen = set()
    unique = []
    for inc in incidents:
        if inc["rule_id"] not in seen:
            seen.add(inc["rule_id"])
            unique.append(inc)

    # Sort by severity
    unique.sort(key=lambda x: SEVERITY_ORDER.index(x["severity"])
                if x["severity"] in SEVERITY_ORDER else 99)

    return unique
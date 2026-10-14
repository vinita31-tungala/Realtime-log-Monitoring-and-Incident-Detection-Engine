"""Real-Time Log Monitoring and Incident Detection Engine.

Standard-library-only defensive training project. It analyzes local synthetic
login events; it does not connect to or probe external systems.
"""
from __future__ import annotations

import argparse
import csv
import ipaddress
import os
import random
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"
REPORTS_DIR = BASE_DIR / "reports"
LOG_FILE = DATA_DIR / "sample_logs.txt"
ACCOUNTS_FILE = BASE_DIR / "accounts.txt"
LOCATIONS_FILE = BASE_DIR / "ip_locations.csv"
HISTORY_FILE = REPORTS_DIR / "event_history.csv"
INCIDENTS_FILE = REPORTS_DIR / "incidents.csv"
SUMMARY_FILE = REPORTS_DIR / "incident_summary.txt"

UNKNOWN_ACCOUNT_THRESHOLD = 3
UNKNOWN_ACCOUNT_WINDOW_SECONDS = 120
PASSWORD_FAILURE_THRESHOLD = 5
PASSWORD_FAILURE_WINDOW_SECONDS = 60
MULTI_ACCOUNT_THRESHOLD = 4
MULTI_ACCOUNT_WINDOW_SECONDS = 120
SUCCESS_AFTER_FAILURE_THRESHOLD = 3
SUCCESS_AFTER_FAILURE_WINDOW_SECONDS = 300
BURST_THRESHOLD = 10
BURST_WINDOW_SECONDS = 60

EVENT_FIELDS = ["timestamp", "source_ip", "username", "event", "reason"]
HISTORY_FIELDS = EVENT_FIELDS + ["classification", "location"]
INCIDENT_FIELDS = [
    "incident_id", "first_seen", "last_seen", "source_ip", "location",
    "incident_type", "severity", "risk_score", "status", "event_count",
    "targeted_usernames", "description", "recommended_action",
]
SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}

# ANSI colors are used only when output is a terminal. Set NO_COLOR=1 to disable.
COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")

def paint(text: str, color: str) -> str:
    codes = {"red": "31", "green": "32", "yellow": "33", "blue": "34", "cyan": "36", "bold": "1", "muted": "90"}
    return f"\033[{codes.get(color, '0')}m{text}\033[0m" if COLOR else text

def now_local() -> datetime:
    return datetime.now().astimezone().replace(microsecond=0)

def ensure_project_files() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    (BASE_DIR / "tests").mkdir(parents=True, exist_ok=True)
    if not ACCOUNTS_FILE.exists():
        ACCOUNTS_FILE.write_text("admin\nhr_manager\nemployee01\nsecurity_team\nfinance_user\n", encoding="utf-8")
    if not LOCATIONS_FILE.exists():
        write_csv(LOCATIONS_FILE, ["source_ip", "location"], [
            {"source_ip": "192.0.2.10", "location": "Example Office Network (test mapping)"},
            {"source_ip": "192.0.2.20", "location": "Example Remote Network (test mapping)"},
        ])
    if not LOG_FILE.exists():
        LOG_FILE.write_text("# Synthetic login events are generated locally by main.py\n", encoding="utf-8")
    if not HISTORY_FILE.exists(): write_csv(HISTORY_FILE, HISTORY_FIELDS, [])
    if not INCIDENTS_FILE.exists(): write_csv(INCIDENTS_FILE, INCIDENT_FIELDS, [])
    if not SUMMARY_FILE.exists(): SUMMARY_FILE.write_text("No monitoring run has been completed yet.\n", encoding="utf-8")

def write_csv(path: Path, fields: list[str], rows: list[dict]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

def read_csv(path: Path) -> list[dict]:
    if not path.exists(): return []
    with path.open("r", newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))

def read_accounts() -> set[str]:
    return {line.strip().lower() for line in ACCOUNTS_FILE.read_text(encoding="utf-8").splitlines()
            if line.strip() and not line.lstrip().startswith("#")}

def read_locations() -> dict[str, str]:
    return {row["source_ip"].strip(): row["location"].strip() for row in read_csv(LOCATIONS_FILE)
            if row.get("source_ip") and row.get("location")}

def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value.strip())

def parse_log_line(line: str) -> dict | None:
    """Parse: ISO_TIMESTAMP source_ip=... username=... event=... reason=..."""
    parts = line.strip().split()
    if len(parts) < 4: return None
    try:
        timestamp = parse_timestamp(parts[0])
        values = {}
        for item in parts[1:]:
            if "=" not in item: return None
            key, value = item.split("=", 1)
            values[key.strip()] = value.strip()
        event = {
            "timestamp": timestamp.isoformat(timespec="seconds"),
            "source_ip": values["source_ip"],
            "username": values["username"].lower(),
            "event": values["event"].lower(),
            "reason": values.get("reason", "unspecified").replace("_", " "),
        }
        ipaddress.ip_address(event["source_ip"])
        if event["event"] not in {"login_failed", "login_success"} or not event["username"]: return None
        return event
    except (ValueError, KeyError):
        return None

def event_key(event: dict) -> tuple:
    return tuple(event.get(field, "") for field in EVENT_FIELDS)

def classify_event(event: dict, accounts: set[str]) -> str:
    if event["event"] == "login_success": return "SUCCESSFUL_LOGIN"
    if event["username"].lower() not in accounts: return "UNKNOWN_ACCOUNT_ATTEMPT"
    return "FAILED_PASSWORD_ATTEMPT"

def load_log_events() -> tuple[list[dict], int]:
    events, invalid = [], 0
    if not LOG_FILE.exists(): return events, invalid
    with LOG_FILE.open("r", encoding="utf-8") as handle:
        for line_number, line in enumerate(handle, start=1):
            if not line.strip() or line.lstrip().startswith("#"): continue
            parsed = parse_log_line(line)
            if parsed is None:
                invalid += 1
                print(paint(f"[WARN] Ignoring malformed log line {line_number}.", "yellow"))
            else: events.append(parsed)
    events.sort(key=lambda event: event["timestamp"])
    return events, invalid

def in_window(events: list[dict], end_index: int, seconds: int) -> list[dict]:
    end_time = parse_timestamp(events[end_index]["timestamp"])
    start_time = end_time - timedelta(seconds=seconds)
    return [event for event in events[:end_index + 1] if start_time <= parse_timestamp(event["timestamp"]) <= end_time]

def make_candidate(incident_type: str, events: list[dict], location: str) -> dict:
    ordered = sorted(events, key=lambda item: item["timestamp"])
    ip = ordered[-1]["source_ip"]
    usernames = sorted({item["username"] for item in ordered})
    count = len(ordered)
    details = {
        "BRUTE_FORCE": ("HIGH", min(94, 60 + count * 5), f"{count} known-account password failures occurred in a short window.", "Review authentication logs; rate-limit or temporarily block the source in a real system."),
        "UNKNOWN_ACCOUNT_ENUMERATION": ("HIGH", min(90, 60 + count * 5), f"{count} attempts used usernames not listed in accounts.txt.", "Check username discovery attempts and review account exposure."),
        "MULTI_ACCOUNT_TARGETING": ("HIGH", min(100, 60 + len(usernames) * 8), f"One IP attempted to access {len(usernames)} different accounts.", "Review the targeted accounts and investigate the source activity."),
        "SUCCESS_AFTER_REPEATED_FAILURES": ("CRITICAL", 95, "A successful login occurred after repeated failures from the same IP.", "Urgently review the session, verify the user, and revoke access if compromise is confirmed."),
        "LOGIN_BURST": ("MEDIUM", min(85, 55 + count * 2), f"{count} login events occurred from one IP within 60 seconds.", "Check whether the burst is expected automation or suspicious activity."),
    }
    severity, score, description, action = details[incident_type]
    return {"first_seen": ordered[0]["timestamp"], "last_seen": ordered[-1]["timestamp"],
            "source_ip": ip, "location": location, "incident_type": incident_type,
            "severity": severity, "risk_score": str(score), "status": "OPEN",
            "event_count": str(count), "targeted_usernames": "; ".join(usernames),
            "description": description, "recommended_action": action}

def detect_incidents(events: list[dict], accounts: set[str], locations: dict[str, str]) -> list[dict]:
    candidates: dict[tuple, dict] = {}
    by_ip: dict[str, list[dict]] = defaultdict(list)
    for event in events: by_ip[event["source_ip"]].append(event)
    for ip, ip_events in by_ip.items():
        ip_events.sort(key=lambda event: event["timestamp"])
        location = locations.get(ip, "Unknown / unmapped location")
        for index, event in enumerate(ip_events):
            two_minutes = in_window(ip_events, index, UNKNOWN_ACCOUNT_WINDOW_SECONDS)
            unknowns = [e for e in two_minutes if classify_event(e, accounts) == "UNKNOWN_ACCOUNT_ATTEMPT"]
            if len(unknowns) >= UNKNOWN_ACCOUNT_THRESHOLD:
                item = make_candidate("UNKNOWN_ACCOUNT_ENUMERATION", unknowns, location)
                candidates[(ip, item["incident_type"])] = item
            failures = [e for e in in_window(ip_events, index, PASSWORD_FAILURE_WINDOW_SECONDS)
                        if e["event"] == "login_failed" and classify_event(e, accounts) == "FAILED_PASSWORD_ATTEMPT"]
            if len(failures) >= PASSWORD_FAILURE_THRESHOLD:
                item = make_candidate("BRUTE_FORCE", failures, location)
                candidates[(ip, item["incident_type"])] = item
            multi = [e for e in two_minutes if e["event"] == "login_failed"]
            if len({e["username"] for e in multi}) >= MULTI_ACCOUNT_THRESHOLD:
                item = make_candidate("MULTI_ACCOUNT_TARGETING", multi, location)
                candidates[(ip, item["incident_type"])] = item
            recent = in_window(ip_events, index, BURST_WINDOW_SECONDS)
            if len(recent) >= BURST_THRESHOLD:
                item = make_candidate("LOGIN_BURST", recent, location)
                candidates[(ip, item["incident_type"])] = item
            if event["event"] == "login_success":
                earlier = [e for e in in_window(ip_events, index, SUCCESS_AFTER_FAILURE_WINDOW_SECONDS)
                           if e["event"] == "login_failed" and parse_timestamp(e["timestamp"]) < parse_timestamp(event["timestamp"])]
                if len(earlier) >= SUCCESS_AFTER_FAILURE_THRESHOLD:
                    item = make_candidate("SUCCESS_AFTER_REPEATED_FAILURES", earlier + [event], location)
                    candidates[(ip, item["incident_type"])] = item
    return list(candidates.values())

def load_history() -> list[dict]: return read_csv(HISTORY_FILE)
def load_incidents() -> list[dict]: return read_csv(INCIDENTS_FILE)

def merge_incidents(existing: list[dict], candidates: list[dict]) -> list[dict]:
    result = [dict(item) for item in existing]
    next_number = 1
    for item in result:
        try: next_number = max(next_number, int(item.get("incident_id", "INC-000000").split("-")[-1]) + 1)
        except ValueError: pass
    for candidate in candidates:
        match = next((item for item in result if item.get("source_ip") == candidate["source_ip"] and item.get("incident_type") == candidate["incident_type"]), None)
        if match:
            previous_status = match.get("status", "OPEN")
            # Keep investigation status and resolved status; do not silently reopen a resolved case.
            match.update(candidate)
            match["status"] = previous_status
        else:
            new_item = dict(candidate)
            new_item["incident_id"] = f"INC-{next_number:06d}"
            next_number += 1
            result.append(new_item)
    for item in result:
        for field in INCIDENT_FIELDS: item.setdefault(field, "")
    return result

def write_summary(events: list[dict], invalid_count: int, incidents: list[dict]) -> None:
    unresolved = [item for item in incidents if item.get("status") != "RESOLVED"]
    severity_counts = Counter(item.get("severity", "UNKNOWN") for item in unresolved)
    type_counts = Counter(item.get("incident_type", "UNKNOWN") for item in unresolved)
    lines = ["REAL-TIME LOG MONITORING AND INCIDENT DETECTION ENGINE", "=" * 58,
             f"Generated: {now_local().isoformat(timespec='seconds')}", f"Events scanned: {len(events)}",
             f"Malformed lines skipped: {invalid_count}", f"Tracked incidents: {len(incidents)}",
             f"Unresolved incidents: {len(unresolved)}", "", "UNRESOLVED BY SEVERITY", "-" * 24]
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW"): lines.append(f"{severity}: {severity_counts[severity]}")
    lines += ["", "INCIDENT TYPE COUNTS", "-" * 20]
    lines += [f"{name}: {count}" for name, count in sorted(type_counts.items())] or ["No unresolved incidents."]
    lines += ["", "INCIDENT DETAILS", "-" * 16]
    for item in sorted(unresolved, key=lambda x: int(x.get("risk_score") or 0), reverse=True):
        lines.extend([f"{item['incident_id']} | {item['severity']} | Risk {item['risk_score']}/100",
                      f"Type: {item['incident_type']} | IP: {item['source_ip']} | Location: {item['location']}",
                      f"Status: {item['status']} | Events: {item['event_count']}", f"Description: {item['description']}",
                      f"Recommended action: {item.get('recommended_action', '')}", ""])
    SUMMARY_FILE.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")

def bar(value: int, maximum: int, width: int = 20) -> str:
    filled = round(width * value / maximum) if maximum else 0
    return "█" * filled + "░" * (width - filled)

def display_dashboard(result: dict) -> None:
    events, incidents = result["events"], result["incidents"]
    unresolved = [item for item in incidents if item.get("status") != "RESOLVED"]
    critical = sum(item.get("severity") == "CRITICAL" for item in unresolved)
    high = sum(item.get("severity") == "HIGH" for item in unresolved)
    successes = sum(item["event"] == "login_success" for item in events)
    failures = len(events) - successes
    width = 86
    print("\n" + paint("╔" + "═" * (width - 2) + "╗", "cyan"))
    print(paint("║  SENTINEL | REAL-TIME LOGIN THREAT MONITOR".ljust(width - 1) + "║", "cyan"))
    print(paint("║  Local synthetic telemetry • Standard-library Python • Defensive lab".ljust(width - 1) + "║", "cyan"))
    print(paint("╚" + "═" * (width - 2) + "╝", "cyan"))
    print(f"  Last scan: {now_local().strftime('%Y-%m-%d %H:%M:%S')}   |   Invalid lines: {result['invalid_count']}   |   Log events: {len(events)}")
    print("  " + "─" * (width - 4))
    print(f"  EVENTS       {len(events):>5}       SUCCESS {successes:>4}       FAILED {failures:>4}       SUCCESS RATE {(100*successes/len(events) if events else 0):5.1f}%")
    print(f"  INCIDENTS    {len(incidents):>5}       UNRESOLVED {len(unresolved):>3}      CRITICAL {critical:>3}       HIGH {high:>3}")
    print("\n  SEVERITY DISTRIBUTION")
    counts = Counter(item.get("severity", "UNKNOWN") for item in unresolved)
    for severity, color in (("CRITICAL", "red"), ("HIGH", "yellow"), ("MEDIUM", "blue"), ("LOW", "green")):
        print("  " + paint(f"{severity:<9} {bar(counts[severity], max(counts.values(), default=1))} {counts[severity]}", color))
    print("\n  PRIORITY QUEUE (top 8 unresolved incidents)")
    print("  " + "─" * (width - 4))
    if not unresolved:
        print("  No unresolved incidents. Run `python main.py --simulate` to generate a test scenario.")
    else:
        print(f"  {'ID':<12} {'SEVERITY':<9} {'RISK':>4}  {'TYPE':<34} {'STATUS':<13}")
        for item in sorted(unresolved, key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "LOW"), 9), -int(x.get("risk_score") or 0)))[:8]:
            sev = item.get("severity", "UNKNOWN")
            print("  " + paint(f"{item.get('incident_id',''):<12} {sev:<9} {int(item.get('risk_score') or 0):>3}/100  {item.get('incident_type',''):<34} {item.get('status',''):<13}", "red" if sev == "CRITICAL" else "yellow" if sev == "HIGH" else "blue"))
            print(f"  {'':12} IP {item.get('source_ip','')}  |  Events {item.get('event_count','0')}  |  {item.get('description','')}")
    print("\n  RECENT ACTIVITY (last 6 events)")
    print("  " + "─" * (width - 4))
    for event in events[-6:]:
        outcome = "SUCCESS" if event["event"] == "login_success" else "FAILED "
        print(f"  {event['timestamp'][:19]:19} {outcome}  {event['source_ip']:<15} user={event['username']:<18} reason={event['reason']}")
    print("\n  REPORTS: reports/event_history.csv | reports/incidents.csv | reports/incident_summary.txt")
    print("  COMMANDS: --help | --simulate | --follow | --incidents | --show INC-000001 | --investigate INC-000001 | --resolve INC-000001")

def process_once(show_dashboard: bool = True) -> dict:
    ensure_project_files()
    accounts, locations = read_accounts(), read_locations()
    events, invalid_count = load_log_events()
    old_history = load_history()
    seen = {event_key(row) for row in old_history}
    new_history = list(old_history)
    for event in events:
        key = event_key(event)
        if key in seen: continue
        seen.add(key)
        new_history.append({**event, "classification": classify_event(event, accounts), "location": locations.get(event["source_ip"], "Unknown / unmapped location")})
    write_csv(HISTORY_FILE, HISTORY_FIELDS, new_history)
    candidates = detect_incidents(events, accounts, locations)
    incidents = merge_incidents(load_incidents(), candidates)
    write_csv(INCIDENTS_FILE, INCIDENT_FIELDS, incidents)
    write_summary(events, invalid_count, incidents)
    result = {"events": events, "invalid_count": invalid_count, "incidents": incidents, "candidates": candidates}
    if show_dashboard: display_dashboard(result)
    return result

def resolve_incident(incident_id: str, new_status: str) -> bool:
    ensure_project_files()
    incidents = load_incidents()
    for item in incidents:
        if item.get("incident_id", "").upper() == incident_id.upper():
            item["status"] = new_status
            write_csv(INCIDENTS_FILE, INCIDENT_FIELDS, incidents)
            events, invalid = load_log_events()
            write_summary(events, invalid, incidents)
            print(paint(f"Updated {incident_id} status to {new_status}.", "green"))
            return True
    print(paint(f"Incident {incident_id} was not found.", "yellow"))
    return False

def show_incident(incident_id: str) -> None:
    item = next((row for row in load_incidents() if row.get("incident_id", "").upper() == incident_id.upper()), None)
    if not item:
        print(f"Incident {incident_id} not found. Run `python main.py` first.")
        return
    print("\n" + "═" * 72)
    print(f" INCIDENT DETAILS: {item['incident_id']}")
    print("═" * 72)
    for field in INCIDENT_FIELDS:
        if field == "incident_id": continue
        print(f"{field.replace('_',' ').title():22}: {item.get(field, '')}")
    print("═" * 72)

def list_incidents(all_items: bool = False) -> None:
    items = load_incidents()
    if not all_items: items = [item for item in items if item.get("status") != "RESOLVED"]
    items.sort(key=lambda x: (SEVERITY_ORDER.get(x.get("severity", "LOW"), 9), -int(x.get("risk_score") or 0)))
    print("\nINCIDENT REGISTER")
    print("-" * 92)
    if not items:
        print("No incidents match this view.")
        return
    print(f"{'ID':<12} {'SEVERITY':<10} {'RISK':>5} {'STATUS':<14} {'TYPE':<36} {'IP':<15}")
    for item in items:
        print(f"{item.get('incident_id',''):<12} {item.get('severity',''):<10} {item.get('risk_score',''):>5} {item.get('status',''):<14} {item.get('incident_type',''):<36} {item.get('source_ip',''):<15}")

def append_simulated_events(count: int = 16, scenario: str = "mixed") -> int:
    """Generate synthetic, non-routable test telemetry locally."""
    ensure_project_files()
    rng = random.Random()
    base = now_local()
    accounts = ["admin", "hr_manager", "employee01", "security_team", "finance_user"]
    unknowns = ["administrator", "root", "superuser", "sysadmin", "payroll", "backup_admin"]
    # Documentation-only IP ranges: these are not real attacker addresses.
    source_ips = ["198.51.100.24", "203.0.113.45", "192.0.2.77"]
    lines = []
    if scenario == "normal":
        for i in range(count):
            user = rng.choice(accounts)
            event = "login_failed" if rng.random() < 0.12 else "login_success"
            reason = "invalid_password" if event == "login_failed" else "none"
            ip = rng.choice(["192.0.2.10", "192.0.2.20", source_ips[2]])
            stamp = (base + timedelta(seconds=i * rng.randint(4, 17))).isoformat(timespec="seconds")
            lines.append(f"{stamp} source_ip={ip} username={user} event={event} reason={reason}")
    else:
        ip = rng.choice(source_ips)
        pattern = [
            ("admin", "login_failed", "invalid_password"),
            ("admin", "login_failed", "invalid_password"),
            ("hr_manager", "login_failed", "invalid_password"),
            (unknowns[0], "login_failed", "unknown_user"),
            (unknowns[1], "login_failed", "unknown_user"),
            (unknowns[2], "login_failed", "unknown_user"),
            ("employee01", "login_failed", "invalid_password"),
            ("security_team", "login_failed", "invalid_password"),
            ("admin", "login_success", "none"),
            ("finance_user", "login_success", "none"),
            ("payroll", "login_failed", "unknown_user"),
            ("backup_admin", "login_failed", "unknown_user"),
            ("admin", "login_failed", "invalid_password"),
            ("hr_manager", "login_success", "none"),
            ("employee01", "login_success", "none"),
            ("security_team", "login_failed", "invalid_password"),
        ]
        if count < len(pattern): pattern = pattern[:count]
        while len(pattern) < count:
            pattern.append((rng.choice(accounts), "login_success", "none") if rng.random() > .25 else (rng.choice(unknowns), "login_failed", "unknown_user"))
        for i, (user, event, reason) in enumerate(pattern):
            stamp = (base + timedelta(seconds=i * 3)).isoformat(timespec="seconds")
            lines.append(f"{stamp} source_ip={ip} username={user} event={event} reason={reason}")
    with LOG_FILE.open("a", encoding="utf-8") as handle:
        if LOG_FILE.stat().st_size and not LOG_FILE.read_text(encoding="utf-8").endswith("\n"): handle.write("\n")
        handle.write("\n".join(lines) + "\n")
    print(paint(f"Generated and appended {len(lines)} local synthetic events (scenario={scenario}).", "green"))
    return len(lines)

def follow_log(interval: float = 2.0, auto_simulate: bool = False) -> None:
    ensure_project_files()
    print(f"Monitoring {LOG_FILE}. Press Ctrl+C to stop.")
    last_size = -1
    try:
        while True:
            size = LOG_FILE.stat().st_size
            if size != last_size:
                process_once(show_dashboard=True)
                last_size = size
            if auto_simulate:
                append_simulated_events(count=random.randint(4, 8), scenario=random.choice(["mixed", "normal"]))
            time.sleep(max(.5, interval))
    except KeyboardInterrupt:
        print("\nMonitoring stopped safely.")

def reset_reports() -> None:
    ensure_project_files()
    write_csv(HISTORY_FILE, HISTORY_FIELDS, [])
    write_csv(INCIDENTS_FILE, INCIDENT_FIELDS, [])
    LOG_FILE.write_text("# Synthetic login events are generated locally by main.py\n", encoding="utf-8")
    SUMMARY_FILE.write_text("Reports reset. Run python main.py --simulate to generate new synthetic activity.\n", encoding="utf-8")
    print(paint("Reports and local log history reset.", "green"))

def main() -> None:
    parser = argparse.ArgumentParser(description="Standard-library Python security log monitor")
    parser.add_argument("--follow", action="store_true", help="watch the log file for changes")
    parser.add_argument("--live-sim", action="store_true", help="continuously simulate events while monitoring")
    parser.add_argument("--simulate", action="store_true", help="generate synthetic events and analyze them")
    parser.add_argument("--scenario", choices=["mixed", "normal"], default="mixed", help="simulation pattern (default: mixed)")
    parser.add_argument("--count", type=int, default=16, help="number of events to generate with --simulate")
    parser.add_argument("--interval", type=float, default=5.0, help="poll/simulation interval in seconds")
    parser.add_argument("--incidents", action="store_true", help="list incidents instead of showing dashboard")
    parser.add_argument("--all-incidents", action="store_true", help="include resolved incidents in incident list")
    parser.add_argument("--show", metavar="INCIDENT_ID", help="show full details for one incident")
    parser.add_argument("--resolve", metavar="INCIDENT_ID", help="mark an incident resolved")
    parser.add_argument("--investigate", metavar="INCIDENT_ID", help="mark an incident investigating")
    parser.add_argument("--reset", action="store_true", help="clear local generated logs and reports")
    args = parser.parse_args()
    ensure_project_files()
    if args.reset: reset_reports()
    elif args.resolve: resolve_incident(args.resolve, "RESOLVED")
    elif args.investigate: resolve_incident(args.investigate, "INVESTIGATING")
    elif args.show: show_incident(args.show)
    elif args.incidents or args.all_incidents: list_incidents(all_items=args.all_incidents)
    elif args.simulate:
        append_simulated_events(count=max(1, min(args.count, 1000)), scenario=args.scenario)
        process_once()
    elif args.live_sim:
        process_once()
        follow_log(max(.5, args.interval), auto_simulate=True)
    elif args.follow:
        process_once()
        follow_log(max(.5, args.interval))
    else:
        # A fresh project automatically gets a small synthetic run; no dataset is needed.
        events, _ = load_log_events()
        if not events: append_simulated_events(count=16, scenario="mixed")
        process_once()

if __name__ == "__main__":
    main()

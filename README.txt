SENTINEL - REAL-TIME LOG MONITORING AND INCIDENT DETECTION ENGINE
=================================================================

Python standard library only. No external dataset, database, or pip install is required.
Synthetic events are generated locally and use documentation-only IP addresses.

QUICK START (VS CODE / WINDOWS)
1. Extract the ZIP file.
2. Open the RealTimeLogMonitor folder in VS Code.
3. Open Terminal > New Terminal.
4. Run: python main.py

COMMANDS
python main.py                              Dashboard and analyze current events
python main.py --simulate                   Generate synthetic attack-pattern events
python main.py --simulate --scenario normal Generate mostly normal login traffic
python main.py --simulate --count 40        Generate 40 synthetic events
python main.py --live-sim                  Continuously simulate and monitor events
python main.py --follow                    Monitor sample_logs.txt for changes
python main.py --incidents                 List unresolved incidents
python main.py --all-incidents             Include resolved incidents
python main.py --show INC-000001           Show full incident details
python main.py --investigate INC-000001    Mark incident as INVESTIGATING
python main.py --resolve INC-000001        Mark incident as RESOLVED
python main.py --reset                     Reset local generated logs and reports
python -m unittest discover -s tests -v    Run automated tests

DETECTION RULES
- BRUTE_FORCE: repeated known-account password failures in a short time window.
- UNKNOWN_ACCOUNT_ENUMERATION: repeated attempts against unknown usernames.
- MULTI_ACCOUNT_TARGETING: one IP attempts multiple different usernames.
- SUCCESS_AFTER_REPEATED_FAILURES: success after repeated failures from the same IP.
- LOGIN_BURST: many login events from one IP within a short window.

FILES
main.py                         Monitoring, detection, simulation, and CLI dashboard
accounts.txt                    Authorized demo usernames
ip_locations.csv                Optional illustrative IP labels, not real geolocation
data/sample_logs.txt            Locally generated synthetic event log
reports/event_history.csv       Generated parsed event history
reports/incidents.csv           Generated incident register
reports/incident_summary.txt    Generated readable summary
 tests/test_monitor.py           Automated unit tests

NOTE
This is a local educational simulation, not an enterprise SIEM or a real-time sensor
for a production identity provider. It does not block IPs or connect to external systems.

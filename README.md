# IdentityWatch 🛂

> Detection-as-code for the way attackers actually break in now: **they log in.** IdentityWatch scans auth logs for identity-first attacks and emits MITRE ATT&CK-mapped alerts.

[![CI](https://github.com/YAMRAJ13y/identitywatch/actions/workflows/ci.yml/badge.svg)](https://github.com/YAMRAJ13y/identitywatch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK%20mapped-red.svg)](https://attack.mitre.org/)

In 2026 the dominant breach pattern isn't malware — it's **valid accounts**. Attackers phish or buy credentials, spray them, bomb users with MFA prompts until one taps "approve," steal session cookies, and sign in from a new country. SOC analyst and detection-engineering roles are the #1 entry point in security, and the skill they hire for is exactly this: **turning attacker behavior into detections that fire on real logs.**

IdentityWatch is a small, readable **detection-as-code** engine that does that — and runs on a bundled sample log with **zero dependencies and no API key**, so it's instantly demoable and CI-tested.

```bash
git clone https://github.com/YAMRAJ13y/identitywatch && cd identitywatch
python -m identitywatch scan examples/sample_auth_log.jsonl
```

---

## ⚡ What it looks like

```
# IdentityWatch — Alert Report
Source: examples/sample_auth_log.jsonl · Events: 30 · Users: 12 · Rules: 6
Alerts: 6 — 🔴 5 high · 🟠 1 medium

🔴 IW001 Impossible travel — HIGH · user: alice
   alice signed in from New York then Moscow (~7510 km apart) within 0.4h (18025 km/h).
   ATT&CK: T1078 Valid Accounts (TA0001)

🔴 IW002 MFA fatigue / bombing — HIGH · user: bob
   bob received 6 MFA prompts within 10 min and one was then approved — likely fatigue compromise.
   ATT&CK: T1621 Multi-Factor Authentication Request Generation (TA0001)
```

Each alert carries the offending user, the evidence events, a MITRE ATT&CK mapping, and a concrete response recommendation.

---

## 🔍 What it detects

| Rule | Detection | MITRE ATT&CK |
|------|-----------|--------------|
| `IW001` | **Impossible travel** — same user, two logins too far apart to fly between | T1078 Valid Accounts |
| `IW002` | **MFA fatigue / bombing** — a burst of MFA prompts, then an approval | T1621 MFA Request Generation |
| `IW003` | **Password spraying** — one IP, many distinct users, many failures | T1110.003 Password Spraying |
| `IW004` | **Brute force / credential stuffing** — many failures for one user, then a success | T1110 Brute Force |
| `IW005` | **New-country sign-in** — a successful login from a country never seen for that user | T1078 Valid Accounts |
| `IW006` | **Session token reuse** — one session cookie used from multiple IPs/countries | T1539 Steal Web Session Cookie |

Full thresholds and rationale: [`docs/DETECTIONS.md`](docs/DETECTIONS.md).

---

## 🧩 Detection-as-code

Every detection is a plain function `detect(events) -> list[Alert]` registered in `RULES`. Adding one is just writing a function and appending it — the engine, report, CLI, and tests pick it up automatically:

```python
def detect_impossible_travel(events):
    # ... group by user, compare consecutive logins, flag > 900 km/h ...
    return alerts

RULES = [detect_impossible_travel, detect_mfa_fatigue, ...]
```

Each rule ships with **positive tests** (fires on the planted attack) and the suite includes a **no-false-positive test** (stays silent on benign traffic) — the discipline real detection engineering is judged on.

---

## 🔧 Usage

```bash
python -m identitywatch scan examples/sample_auth_log.jsonl          # markdown
python -m identitywatch scan auth.jsonl --json                       # machine-readable
python -m identitywatch scan auth.csv --fail-on medium               # CI gate
```

`scan` reads **JSONL / JSON / CSV** with fields: `timestamp, user, ip, event_type` (+ optional `country, city, lat, lon, asn, user_agent, session_id`). It exits non-zero when an alert at/above `--fail-on` (default `high`) is present, so it drops into a detection-as-code pipeline.

**Editable install** adds the `identitywatch` command; `pip install -e ".[llm]"` + `ANTHROPIC_API_KEY` enables `--llm` Claude triage narratives on each alert.

---

## ✅ Testing & CI

```bash
ruff check .   # lint
pytest -q      # every rule fires on the sample; none fire on benign traffic
```

GitHub Actions runs lint + tests on Python 3.10–3.13 and verifies the sample log raises high-severity alerts — all offline, no secrets.

---

## 🚧 Roadmap

- [ ] Export detections as [Sigma](https://github.com/SigmaHQ/sigma) rules
- [ ] Enrich source IPs via GreyNoise / AbuseIPDB (pairs with [IOCForge](https://github.com/YAMRAJ13y/iocforge))
- [ ] Native Okta / Entra ID (Azure AD) sign-in log field mappings
- [ ] Per-user baselining (typical countries/ASNs/hours) to cut false positives
- [ ] Streaming mode for continuous monitoring

---

## ⚠️ Disclaimer

IdentityWatch is a defensive detection tool. The bundled `examples/sample_auth_log.jsonl` is synthetic. Tune the thresholds in `docs/DETECTIONS.md` to your environment before relying on it operationally.

---

## 📄 License

[MIT](LICENSE) © 2026 Yamraj ([@YAMRAJ13y](https://github.com/YAMRAJ13y))

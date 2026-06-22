# Detections reference

Each detection is a function in `src/identitywatch/rules.py`, registered in `RULES`.
Thresholds are sensible defaults — tune them to your environment.

## IW001 — Impossible travel
**T1078 Valid Accounts (TA0001)** · severity high

Groups `login_success` events (with geo coords) per user, walks consecutive logins,
and flags any pair whose implied speed exceeds **900 km/h** over a distance of more
than **500 km** (faster than a commercial flight ⇒ two simultaneous sessions).

## IW002 — MFA fatigue / bombing
**T1621 Multi-Factor Authentication Request Generation (TA0001)** · high / medium

Flags a user who receives **≥ 5 MFA prompts** (`mfa_challenge` / `mfa_denied`) within
a **10-minute** window. If an `mfa_approved` follows the burst, severity is **high**
(likely the user caved — fatigue compromise); otherwise **medium** (bombing attempt).

## IW003 — Password spraying
**T1110.003 Brute Force: Password Spraying (TA0006)** · high

Groups `login_failure` by source IP and flags any IP that fails against **≥ 5 distinct
users** within a **15-minute** window — the low-and-slow spray pattern that evades
per-account lockouts.

## IW004 — Brute force / credential stuffing
**T1110 Brute Force (TA0006)** · high / medium

Flags a single user with **≥ 6 failed logins** in a **10-minute** window. If a
`login_success` follows within 10 minutes, severity is **high** (likely account
takeover); otherwise **medium**.

## IW005 — New-country sign-in
**T1078 Valid Accounts (TA0001)** · medium

Processes events chronologically per user and flags the first `login_success` from a
country not previously seen for that user. Pairs strongly with IW001/IW006 — a new
country *plus* impossible travel or session reuse is a high-confidence takeover.

## IW006 — Session token reuse
**T1539 Steal Web Session Cookie (TA0006)** · high

Groups `login_success` / `token_use` by `session_id` and flags any session used from
**more than one IP across more than one country** — the signature of a stolen session
cookie being replayed (the post-MFA bypass behind several 2025–2026 intrusions).

## Tuning notes
- Thresholds (`window_min`, `threshold`, `min_users`) are function parameters — adjust per environment noise.
- IW001 needs `lat`/`lon`; without geo data it simply skips (no false positives).
- Add per-user baselining (typical countries/ASNs/hours) to further cut benign new-country/new-ASN noise.

"""আসল Loghub OpenSSH ডেটা থেকে test fixture বানায়। চালাও: python tests/build_cases.py"""
import json
import os

import pandas as pd

SRC = "data/real/raw_real.csv"
OUT = "tests/fixtures"

# label: attack = একই IP থেকে ≥5 failed; benign = ≤1 failed বা শুধু সফল login
CASES = [
    ("183.62.140.253", "easy", "attack", "286 failed, 10 users"),
    ("112.95.230.3", "easy", "attack", "26 failed, 3 users, 1 min"),
    ("185.190.58.151", "easy", "attack", "17 failed, 3 users, 5 min"),
    ("123.235.32.19", "easy", "attack", "7 failed, 1 user, 2 min"),
    ("119.4.203.64", "easy", "attack", "6 failed, 1 user, 12 sec"),
    ("119.137.62.142", "easy", "benign", "only successful login (fztu)"),
    ("191.210.223.172", "easy", "benign", "1 failed"),
    ("103.207.39.165", "easy", "benign", "1 failed"),
    ("175.102.13.6", "easy", "benign", "1 failed"),
    ("88.147.143.242", "easy", "benign", "1 failed"),
    ("187.141.143.180", "hard", "attack", "password spraying: 80 failed, 28 users"),
    ("103.99.0.122", "hard", "attack", "46 failed over 19 users, 2 hours"),
    ("5.188.10.180", "hard", "attack", "17 failed spread over 6 users"),
    ("52.80.34.196", "hard", "attack", "slow: 5 failed over 3 hours, 3 users"),
    ("60.2.12.12", "hard", "attack", "boundary: exactly 5 failed, 1 user"),
]

os.makedirs(OUT, exist_ok=True)
df = pd.read_csv(SRC, dtype=str, keep_default_na=False)
df["country"] = "UNKNOWN"          # লগে দেশের তথ্য নেই
df.to_csv(f"{OUT}/real_events.csv", index=False)

stats = df[df.event == "login_failed"].groupby("ip").agg(
    failures=("user", "size"), users=("user", "nunique"))
cases = []
for i, (ip, cat, label, why) in enumerate(CASES, 1):
    assert (df.ip == ip).any(), f"{ip} ডেটায় নেই; ভুল ফাইল?"
    cases.append({"id": f"{cat.upper()[0]}{i:02d}", "category": cat, "ip": ip,
                  "label": label, "why": why,
                  "failures": int(stats.failures.get(ip, 0)),
                  "users": int(stats.users.get(ip, 0))})
with open(f"{OUT}/cases.json", "w", encoding="utf-8") as fh:
    json.dump(cases, fh, indent=2)
print(f"events: {len(df)} | IP cases: {len(cases)} -> {OUT}/")
"""হিডেন সেট বানায়। detector ফ্রিজ করার পরই চালাবে, তারপর শুধু একবার: pytest -m holdout
ব্যবহার: python tests/build_holdout.py data/real/OpenSSH_slice2.log [বছর]"""
import json
import os
import random
import re
import sys
from datetime import datetime

import pandas as pd

if len(sys.argv) < 2:
    sys.exit("ব্যবহার: python tests/build_holdout.py <log-slice> [বছর]")
SRC = sys.argv[1]
YEAR = int(sys.argv[2]) if len(sys.argv) > 2 else 2015
OUT = "tests/holdout"
DEV = "tests/fixtures/real_events.csv"
SEED, N_ATTACK, N_BENIGN = 2026, 5, 5

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
LINE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
                  r"\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAIL = re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
                  r"from " + IP + r" port")
OK = re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
                r"(?P<user>\S+) from " + IP + r" port")

rows, year, prev_month = [], YEAR, None
with open(SRC, encoding="utf-8", errors="replace") as f:
    for raw in f:
        m = LINE.match(raw.strip().lstrip("\ufeff"))
        if not m:
            continue
        fm, om = FAIL.search(m["msg"]), OK.search(m["msg"])
        if not (fm or om):
            continue
        t = datetime.strptime(f"2000 {m['mon']} {m['day']} {m['time']}", "%Y %b %d %H:%M:%S")
        if prev_month and t.month < prev_month:
            year += 1
        prev_month = t.month
        g = fm or om
        rows.append([t.replace(year=year).strftime("%Y-%m-%d %H:%M:%S"), g["user"],
                     g["ip"], "UNKNOWN", "login_failed" if fm else "login_success"])
df = pd.DataFrame(rows, columns=["timestamp", "user", "ip", "country", "event"])

dev_ips = set(pd.read_csv(DEV, dtype=str, keep_default_na=False)["ip"])
fails = df[df.event == "login_failed"].groupby("ip").agg(
    failures=("user", "size"), users=("user", "nunique"),
    first=("timestamp", "min"), last=("timestamp", "max"))
all_ips = set(df["ip"])
fcount = {ip: int(fails.failures.get(ip, 0)) for ip in all_ips}
attack = sorted([ip for ip in all_ips if fcount[ip] >= 5 and ip not in dev_ips],
                key=lambda ip: fcount[ip])
benign = sorted([ip for ip in all_ips if fcount[ip] <= 1 and ip not in dev_ips])
print(f"events: {len(df)} | IPs: {len(all_ips)} | attack candidates: {len(attack)} | "
      f"benign candidates: {len(benign)} | dev IPs excluded: {len(dev_ips & all_ips)}")
if len(attack) < N_ATTACK or len(benign) < N_BENIGN:
    sys.exit("এই slice-এ যথেষ্ট নতুন IP নেই। অন্য অংশ (-Skip বদলে) নিয়ে আবার চেষ্টা করো।")

step = (len(attack) - 1) / (N_ATTACK - 1)
pick_attack = [attack[round(i * step)] for i in range(N_ATTACK)]   # ছোট থেকে বড়, সমান ব্যবধানে
pick_benign = random.Random(SEED).sample(benign, N_BENIGN)

cases = []
for i, (ip, label) in enumerate([(p, "attack") for p in pick_attack] +
                                [(p, "benign") for p in pick_benign], 1):
    st = fails.loc[ip] if ip in fails.index else None
    cases.append({"id": f"X{i:02d}", "ip": ip, "label": label,
                  "failures": fcount[ip], "users": int(st.users) if st is not None else 0,
                  "why": f"{fcount[ip]} failed" + (f", {int(st.users)} users, {st['first'][11:]}-{st['last'][11:]}" if st is not None else ", success only")})

os.makedirs(OUT, exist_ok=True)
df.to_csv(f"{OUT}/real_events.csv", index=False)
with open(f"{OUT}/cases.json", "w", encoding="utf-8") as fh:
    json.dump(cases, fh, indent=2)
print(f"hidden cases: {len(cases)} -> {OUT}/")
for c in cases:
    print(f"  {c['id']} {c['ip']:<16} {c['label']:<7} {c['why']}")
import re
import sys
from collections import Counter
from datetime import datetime

import pandas as pd

SRC = sys.argv[1] if len(sys.argv) > 1 else "data/real/OpenSSH_2k.log"
OUT = "data/real/raw_real.csv"
YEAR = int(sys.argv[2]) if len(sys.argv) > 2 else 2015   # লগে বছর থাকে না

IP = r"(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
LINE = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})"
    r"\s+\S+\s+sshd\[\d+\]:\s+(?P<msg>.*)$")
FAIL = re.compile(
    r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) "
    r"from " + IP + r" port")
OK = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam) for "
    r"(?P<user>\S+) from " + IP + r" port")

rows, skipped, year, prev_month = [], 0, YEAR, None
with open(SRC, encoding="utf-8", errors="replace") as f:
    for raw in f:
        m = LINE.match(raw.strip())
        if not m:
            skipped += 1
            continue
        msg = m["msg"]
        fm, om = FAIL.search(msg), OK.search(msg)
        if not (fm or om):
            skipped += 1
            continue
        t = datetime.strptime(f"2000 {m['mon']} {m['day']} {m['time']}",
                              "%Y %b %d %H:%M:%S")
        if prev_month and t.month < prev_month:
            year += 1                       # Dec -> Jan
        prev_month = t.month
        ts = t.replace(year=year)
        g = fm or om
        rows.append([ts.strftime("%Y-%m-%d %H:%M:%S"), g["user"], g["ip"],
                     "NA", "login_failed" if fm else "login_success"])

df = pd.DataFrame(rows, columns=["timestamp", "user", "ip", "country", "event"])
df.to_csv(OUT, index=False)

print(f"Parsed events: {len(df)} | skipped lines: {skipped}")
print(df["event"].value_counts().to_string())
print("Unique IPs:", df["ip"].nunique(), "| unique users:", df["user"].nunique())
print("\nTop IPs by failed logins:")
print(df[df["event"] == "login_failed"]["ip"].value_counts().head(8).to_string())
print("\nSuccessful logins:")
print(df[df["event"] == "login_success"][["timestamp", "user", "ip"]].to_string())
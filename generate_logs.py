import csv, os, random
from datetime import datetime, timedelta

random.seed(42)
fmt = "%Y-%m-%d %H:%M:%S"
users = {"rahim": "103.12.4.10", "karim": "103.12.4.11",
         "salma": "103.12.4.12", "nusrat": "103.12.4.13"}
rows = []

# স্বাভাবিক login
start = datetime(2026, 10, 1, 9, 0, 0)
for _ in range(40):
    u = random.choice(list(users))
    t = start + timedelta(minutes=random.randint(0, 600))
    rows.append([t.strftime(fmt), u, users[u], "BD", "login_success"])

# আক্রমণ: ১০ বার failed, তারপর success
t = datetime(2026, 10, 2, 3, 15, 0)
for i in range(10):
    rows.append([(t + timedelta(seconds=i * 20)).strftime(fmt),
                 "rahim", "185.220.101.5", "RU", "login_failed"])
rows.append([(t + timedelta(seconds=220)).strftime(fmt),
             "rahim", "185.220.101.5", "RU", "login_success"])

# ইচ্ছাকৃত ভুল ডেটা
rows.append(["2026-10-03 10:00:00", "karim", "", "BD", "login_failed"])
rows.append(["not-a-date", "salma", "103.12.4.12", "BD", "login_success"])
rows.append(["2026-10-03 11:00:00", "nusrat", "999.1.1.1", "BD", "login_failed"])

rows.sort(key=lambda r: r[0])
os.makedirs("data", exist_ok=True)
with open("data/raw_logs.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["timestamp", "user", "ip", "country", "event"])
    w.writerows(rows)
print("data/raw_logs.csv তৈরি হয়েছে:", len(rows), "টি সারি")
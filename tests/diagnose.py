import pandas as pd

import detect
import ingest

raw = pd.read_csv("tests/holdout/real_events.csv", dtype=str, keep_default_na=False)
good, _ = ingest.normalize(raw)
s = detect.score_events(good)

for ip in ["103.207.36.21", "137.59.224.163", "43.231.210.91", "177.197.40.65"]:
    print(ip)
    print(s[s.ip == ip][["timestamp", "user", "risk_score", "reasons"]].to_string(index=False))
    print()
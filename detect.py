import pandas as pd

FAIL_LIMIT = 5
WINDOW = pd.Timedelta(minutes=10)
IP_WINDOW = pd.Timedelta(hours=12)  # IP-ভিত্তিক জানালা (±12 ঘণ্টা)
ODD_HOURS = lambda h: h < 6 or h >= 22
PTS = {"repeated_failures": 40, "success_after_failures": 40,
       "new_country": 25, "new_ip": 20, "odd_hour": 15,
       "ip_repeated_failures": 40}


def build_baseline(df):
    ok = df[df["event"] == "login_success"]
    base = {}
    for user, g in ok.groupby("user"):
        ips, cs = g["ip"].dropna().mode(), g["country"].dropna().mode()
        if ips.empty:
            continue
        base[user] = {"ip": ips.iloc[0],
                      "country": cs.iloc[0] if not cs.empty else "UNKNOWN"}
    return base


def level(score):
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    if score > 0:
        return "low"
    return "none"


def score_events(df):
    if df.empty:
        return df.assign(risk_score=[], risk_level=[], reasons=[])
    base = build_baseline(df)
    ip_fails = {ip: g["timestamp"] for ip, g in
                df[df["event"] == "login_failed"].groupby("ip")}
    out = []
    for _, r in df.iterrows():
        score, reasons = 0, []
        u, t = r["user"], r["timestamp"]
        fails = df[(df["user"] == u) & (df["event"] == "login_failed")]
        if r["event"] == "login_failed":
            near = fails[(fails["timestamp"] >= t - WINDOW) &
                         (fails["timestamp"] <= t + WINDOW)]
            if len(near) >= FAIL_LIMIT:
                score += PTS["repeated_failures"]
                reasons.append(f"repeated_failures({len(near)} in 10min)")
        # Rule 1b: একই IP থেকে দীর্ঘ জানালায় বারবার failed (ধীর আক্রমণ)
        if r["event"] == "login_failed":
            ts = ip_fails[r["ip"]]
            n = int(((ts >= t - IP_WINDOW) & (ts <= t + IP_WINDOW)).sum())
            if n >= FAIL_LIMIT:
                score += PTS["ip_repeated_failures"]
                reasons.append(f"ip_repeated_failures({n} in 24h)")
        if r["event"] == "login_success":
            prev = fails[(fails["timestamp"] >= t - WINDOW) &
                         (fails["timestamp"] < t)]
            if len(prev) >= FAIL_LIMIT:
                score += PTS["success_after_failures"]
                reasons.append(f"success_after_{len(prev)}_failures")
        if u in base:
            if (pd.notna(r["country"]) and r["country"] != base[u]["country"]
                    and "UNKNOWN" not in (r["country"], base[u]["country"])):
                score += PTS["new_country"]
                reasons.append(f"new_country({r['country']})")
            if r["ip"] != base[u]["ip"]:
                score += PTS["new_ip"]
                reasons.append(f"new_ip({r['ip']})")
        if ODD_HOURS(t.hour):
            score += PTS["odd_hour"]
            reasons.append(f"odd_hour({t.hour}:00)")
        score = min(score, 100)
        out.append({**r.to_dict(), "risk_score": score,
                    "risk_level": level(score), "reasons": "; ".join(reasons)})
    return pd.DataFrame(out)
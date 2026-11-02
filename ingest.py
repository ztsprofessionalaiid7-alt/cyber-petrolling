import ipaddress, re, sys
import pandas as pd

REQUIRED = ["timestamp", "user", "ip", "country", "event"]
EVENTS = ["login_failed", "login_success"]
CONTROL = re.compile(r"[\x00-\x1f\x7f]+")


def load(path):
    if path.lower().endswith(".json"):
        return pd.read_json(path, dtype=str)
    return pd.read_csv(path, dtype=str, keep_default_na=False)


def valid_ip(x):
    try:
        ipaddress.ip_address(x)
        return True
    except ValueError:
        return False


def sanitize(text):
    """নিয়ন্ত্রণ-অক্ষর বাদ; = + - @ দিয়ে শুরু হলে সামনে ' (CSV injection রোধ)।"""
    text = CONTROL.sub(" ", str(text)).strip()
    if text[:1] in ("=", "+", "-", "@"):
        text = "'" + text
    return text


def normalize(df):
    df = df.copy()
    df.columns = [c.strip().lower() for c in df.columns]
    missing = [c for c in REQUIRED if c not in df.columns]
    if missing:
        raise ValueError(f"কলাম নেই: {missing}")

    df = df[REQUIRED].fillna("").astype(str)
    for c in REQUIRED:
        df[c] = df[c].str.strip()
    df["event"] = df["event"].str.lower()
    df["user"] = df["user"].apply(sanitize)
    df["country"] = df["country"].apply(sanitize)
    df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")

    df["reject_reason"] = ""
    df.loc[df["timestamp"].isna(), "reject_reason"] += "invalid_timestamp;"
    df.loc[~df["ip"].apply(valid_ip).astype(bool), "reject_reason"] += "invalid_ip;"
    df.loc[~df["event"].isin(EVENTS), "reject_reason"] += "unknown_event;"
    df.loc[df["user"] == "", "reject_reason"] += "missing_user;"

    good = df[df["reject_reason"] == ""].drop(columns="reject_reason")
    bad = df[df["reject_reason"] != ""]
    good = good.drop_duplicates().sort_values("timestamp").reset_index(drop=True)
    return good, bad


if __name__ == "__main__":
    path = sys.argv[1] if len(sys.argv) > 1 else "data/raw_logs.csv"
    good, bad = normalize(load(path))
    good.to_csv("data/normalized.csv", index=False)
    bad.to_csv("data/rejected.csv", index=False)
    print(f"accepted: {len(good)} | rejected: {len(bad)}")
    if len(bad):
        print(bad[["timestamp", "user", "ip", "reject_reason"]].to_string())
import json
import os
import re
import time

import pandas as pd
from dotenv import load_dotenv

load_dotenv()

MODEL = "gemini-3.1-flash-lite"
MIN_SCORE = 40                      # medium বা তার ওপরের event
GROUP_GAP = pd.Timedelta(minutes=10)
RETRIES = 5                         # Gemini সর্বোচ্চ কতবার চেষ্টা হবে
TEMPORARY_CODES = (429, 500, 503, 504)


def build_incidents(scored):
    """একই user + IP-এর কাছাকাছি event-গুলোকে এক ঘটনায় গ্রুপ করে।"""
    ev = scored[scored["risk_score"] >= MIN_SCORE].copy()
    ev["timestamp"] = pd.to_datetime(ev["timestamp"])
    ev = ev.sort_values("timestamp")

    incidents = []
    for (user, ip), g in ev.groupby(["user", "ip"]):
        g = g.sort_values("timestamp")
        start = 0
        rows = list(g.itertuples())
        for i in range(1, len(rows) + 1):
            if i == len(rows) or rows[i].timestamp - rows[i - 1].timestamp > GROUP_GAP:
                chunk = g.iloc[start:i]
                incidents.append(make_incident(user, ip, chunk))
                start = i

    incidents.sort(key=lambda x: x["first_seen"])
    for n, inc in enumerate(incidents, 1):
        inc["incident_id"] = f"INC-{n:03d}"
    return incidents


def make_incident(user, ip, chunk):
    rule_types = set()
    for r in chunk["reasons"].fillna(""):
        for part in r.split(";"):
            name = re.sub(r"\(.*?\)", "", part).strip()
            name = re.sub(r"_\d+_", "_N_", name)
            if name:
                rule_types.add(name)
    return {
        "user": user,
        "ip": ip,
        "country": chunk["country"].iloc[0],
        "first_seen": str(chunk["timestamp"].min()),
        "last_seen": str(chunk["timestamp"].max()),
        "failed_logins": int((chunk["event"] == "login_failed").sum()),
        "successful_logins": int((chunk["event"] == "login_success").sum()),
        "max_risk_score": int(chunk["risk_score"].max()),
        "rules_triggered": sorted(rule_types),
        "possible_account_takeover": bool(
            chunk["reasons"].fillna("").str.contains("success_after").any()
        ),
    }


def fallback_summary(inc):
    text = (
        f"User '{inc['user']}' had {inc['failed_logins']} failed login(s) from "
        f"{inc['ip']} ({inc['country']}) between {inc['first_seen']} and "
        f"{inc['last_seen']}, followed by {inc['successful_logins']} successful "
        f"login(s). Max risk score: {inc['max_risk_score']}."
    )
    steps = ["Review the activity for this user and IP manually."]
    if inc["possible_account_takeover"]:
        steps = [
            f"Verify with '{inc['user']}' whether the successful login was theirs.",
            "Consider resetting the password and revoking active sessions.",
            f"Check whether {inc['ip']} appears in other accounts' logs.",
        ]
    return {"summary": text, "next_steps": steps, "source": "fallback_rules"}


def gemini_summary(inc, retries=RETRIES):
    """Gemini ব্যর্থ হলে None ফেরত দেয়; detection তাতে থামে না।"""
    key = os.environ.get("GEMINI_API_KEY")
    if not key:
        print("  GEMINI_API_KEY not set -> fallback")
        return None

    from google import genai
    from google.genai import types

    client = genai.Client(
        api_key=key, http_options=types.HttpOptions(timeout=30000)
    )
    prompt = (
        "You are a security analyst assistant. Using ONLY the facts below, "
        "write a short incident summary (2-3 sentences) and exactly 3 suggested "
        "next steps. Do not invent facts, names, or numbers. Do not give a final "
        "verdict; say 'possible' or 'suspected' where appropriate.\n"
        "Next steps must be specific, actionable security actions "
        "(e.g., reset password, revoke sessions, block IP at firewall), "
        "not generic instructions to investigate. Phrase them as recommendations "
        "for a human to perform; never say an action was already taken. "
        "Only recommend an action that fits the facts "
        "(for example, recommend resetting the password and revoking sessions "
        "only if a successful login followed the failures).\n"
        'Return JSON: {"summary": string, "next_steps": [string, string, string]}\n\n'
        f"Facts:\n{json.dumps(inc, indent=2)}"
    )

    for attempt in range(1, retries + 1):
        try:
            resp = client.models.generate_content(
                model=MODEL,
                contents=prompt,
                config={"response_mime_type": "application/json"},
            )
            data = json.loads(resp.text)
            if not isinstance(data.get("summary"), str) or not isinstance(
                data.get("next_steps"), list
            ):
                raise ValueError("unexpected response shape")
            return {"summary": data["summary"],
                    "next_steps": data["next_steps"], "source": "gemini"}
        except Exception as e:
            code = getattr(e, "code", None)
            print(f"  Gemini attempt {attempt}/{retries} failed "
                  f"({type(e).__name__}, code={code})")
            if code in TEMPORARY_CODES and attempt < retries:
                wait = 2 ** attempt          # ২, ৪, ৮, ১৬ সেকেন্ড
                print(f"  retrying in {wait}s...")
                time.sleep(wait)
                continue
            print("  -> fallback")
            return None


if __name__ == "__main__":
    scored = pd.read_csv("data/scored.csv")
    incidents = build_incidents(scored)
    print(f"Incidents found: {len(incidents)}\n")

    for inc in incidents:
        result = gemini_summary(inc) or fallback_summary(inc)
        inc.update(result)
        print(f"[{inc['incident_id']}] score={inc['max_risk_score']} "
              f"source={inc['source']}")
        print(" ", inc["summary"])
        for s in inc["next_steps"]:
            print("   -", s)
        print()

    with open("data/incidents.json", "w", encoding="utf-8") as f:
        json.dump(incidents, f, indent=2, ensure_ascii=False)
    print("Saved: data/incidents.json")
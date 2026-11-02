import json
import os
import re
import sys

import requests
from dotenv import load_dotenv

load_dotenv()

INCIDENTS_FILE = "data/incidents.json"
SENT_FILE = "data/sent_alerts.json"
MIN_SCORE = 70            # এর নিচের score-এ alert যাবে না
TIMEOUT = 10


def incident_key(inc):
    """একই ঘটনার জন্য সবসময় একই চিহ্ন (duplicate আটকাতে)।"""
    return f"{inc['user']}|{inc['ip']}|{inc['first_seen']}"


def load_sent():
    if not os.path.exists(SENT_FILE):
        return set()
    try:
        with open(SENT_FILE, encoding="utf-8") as f:
            return set(json.load(f))
    except (json.JSONDecodeError, OSError):
        print("WARNING: sent_alerts.json unreadable, starting fresh")
        return set()


def save_sent(sent):
    os.makedirs("data", exist_ok=True)
    with open(SENT_FILE, "w", encoding="utf-8") as f:
        json.dump(sorted(sent), f, indent=2)


def safe_subject(inc):
    """নতুন লাইন বাদ দেয়, যাতে ইমেইল header injection না হয়।"""
    user = re.sub(r"[\x00-\x1f\x7f]+", " ", str(inc["user"]))
    return (f"[Security Alert] {inc['incident_id']} - "
            f"risk {inc['max_risk_score']}/100 - user {user}")


def build_message(inc):
    steps = "\n".join(f"- {s}" for s in inc.get("next_steps", []))
    return (
        f"Security Alert {inc['incident_id']} "
        f"(risk {inc['max_risk_score']}/100)\n\n"
        f"User: {inc['user']}\n"
        f"IP: {inc['ip']} ({inc['country']})\n"
        f"Time: {inc['first_seen']} to {inc['last_seen']}\n"
        f"Failed logins: {inc['failed_logins']} | "
        f"Successful: {inc['successful_logins']}\n"
        f"Possible account takeover: {inc['possible_account_takeover']}\n\n"
        f"Summary ({inc.get('source', 'unknown')}):\n{inc.get('summary', '')}\n\n"
        f"Suggested next steps:\n{steps}\n\n"
        "Alert only. No automatic action was taken."
    )


def send_alert(url, inc):
    subject = safe_subject(inc)
    payload = {**inc, "subject": subject, "message": build_message(inc)}
    r = requests.post(url, json=payload, timeout=TIMEOUT)
    if r.status_code == 404:
        raise RuntimeError(
            "404: webhook not listening. Test URL হলে n8n-এ "
            "'Listen for test event' চাপো; Production URL হলে workflow Active করো।"
        )
    r.raise_for_status()


if __name__ == "__main__":
    force = "--force" in sys.argv          # duplicate চেক এড়িয়ে আবার পাঠাতে
    url = os.environ.get("N8N_WEBHOOK_URL")
    if not url:
        sys.exit("N8N_WEBHOOK_URL is not set in .env")
    if not os.path.exists(INCIDENTS_FILE):
        sys.exit("data/incidents.json not found. Run summarize.py first.")

    with open(INCIDENTS_FILE, encoding="utf-8") as f:
        incidents = json.load(f)

    sent = load_sent()
    sent_n = skipped_dup = skipped_low = failed = 0

    for inc in incidents:
        if inc["max_risk_score"] < MIN_SCORE:
            skipped_low += 1
            continue
        key = incident_key(inc)
        if key in sent and not force:
            print(f"[{inc['incident_id']}] already alerted -> skipped")
            skipped_dup += 1
            continue
        try:
            send_alert(url, inc)
        except requests.exceptions.ConnectionError:
            print(f"[{inc['incident_id']}] FAILED: n8n unreachable "
                  "(Docker/n8n চালু আছে?)")
            failed += 1
        except Exception as e:
            print(f"[{inc['incident_id']}] FAILED: {e}")
            failed += 1
        else:
            sent.add(key)
            save_sent(sent)               # শুধু সফল হলে সেভ হয়
            print(f"[{inc['incident_id']}] alert sent")
            sent_n += 1

    print(f"\nSent: {sent_n} | Duplicates skipped: {skipped_dup} | "
          f"Below threshold: {skipped_low} | Failed: {failed}")
    sys.exit(1 if failed else 0)
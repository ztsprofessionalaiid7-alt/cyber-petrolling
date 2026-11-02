import json
import os

import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI Cyber Patrol Agent", layout="wide")
st.title("AI Cyber Patrol Agent")
st.caption("Rule-based detection + Gemini summary + n8n alert. "
           "Alert only: no automatic blocking.")

SCORED, INCIDENTS_F, SENT = ("data/scored.csv", "data/incidents.json",
                             "data/sent_alerts.json")

if not os.path.exists(SCORED):
    st.error("data/scored.csv পাওয়া যায়নি। আগে চালাও: generate_logs.py, "
             "ingest.py, detect.py, summarize.py")
    st.stop()

scored = pd.read_csv(SCORED, keep_default_na=False)
scored["timestamp"] = pd.to_datetime(scored["timestamp"])
scored["risk_score"] = pd.to_numeric(scored["risk_score"])

incidents = []
if os.path.exists(INCIDENTS_F):
    with open(INCIDENTS_F, encoding="utf-8") as f:
        incidents = json.load(f)
sent = set()
if os.path.exists(SENT):
    try:
        with open(SENT, encoding="utf-8") as f:
            sent = set(json.load(f))
    except (json.JSONDecodeError, OSError):
        pass

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total events", len(scored))
c2.metric("Flagged (score > 0)", int((scored["risk_score"] > 0).sum()))
c3.metric("High risk", int((scored["risk_level"] == "high").sum()))
c4.metric("Incidents", len(incidents))

st.subheader("Incidents")
if not incidents:
    st.info("কোনো incident নেই (data/incidents.json খালি বা নেই)।")
for inc in incidents:
    key = f"{inc['user']}|{inc['ip']}|{inc['first_seen']}"
    status = "alert sent" if key in sent else "not alerted"
    title = (f"{inc['incident_id']} | user {inc['user']} | {inc['ip']} "
             f"({inc['country']}) | risk {inc['max_risk_score']}/100 | {status}")
    with st.expander(title, expanded=True):
        a, b = st.columns([2, 1])
        with a:
            st.markdown(f"**Summary** (`{inc.get('source', 'unknown')}`): "
                        f"{inc.get('summary', '')}")
            st.markdown("**Suggested next steps** (সুপারিশ, স্বয়ংক্রিয় কাজ নয়):")
            for s in inc.get("next_steps", []):
                st.markdown(f"- {s}")
            st.caption("Gemini-র লেখা সারাংশ চূড়ান্ত security verdict নয়; "
                       "human review দরকার।")
        with b:
            st.write(f"Time: {inc['first_seen']} → {inc['last_seen']}")
            st.write(f"Failed: {inc['failed_logins']} | "
                     f"Success: {inc['successful_logins']}")
            st.write(f"Possible account takeover: {inc['possible_account_takeover']}")
            st.write("Rules: " + ", ".join(inc.get("rules_triggered", [])))

st.subheader("Risk distribution")
order = ["none", "low", "medium", "high"]
counts = scored["risk_level"].value_counts().reindex(order, fill_value=0)
st.bar_chart(counts)

st.subheader("Events")
level = st.multiselect("Risk level", order, default=["medium", "high"])
users = sorted(scored["user"].unique())
user = st.selectbox("User", ["(all)"] + users)
view = scored[scored["risk_level"].isin(level)]
if user != "(all)":
    view = view[view["user"] == user]
st.dataframe(
    view[["timestamp", "user", "ip", "country", "event",
          "risk_score", "risk_level", "reasons"]].sort_values("timestamp"),
    use_container_width=True, hide_index=True)
"""হিডেন ১০টি কেস। ডিফল্টে চলে না। detector ফ্রিজ করার পর শুধু একবার: python -m pytest tests -m holdout -v
Label: ≥5 failed একই IP থেকে = attack (score ≥ 40); ≤1 failed = benign (score < 40)।"""
import json
import os

import pandas as pd
import pytest

import detect
import ingest

pytestmark = pytest.mark.holdout
HOLD = os.path.join(os.path.dirname(__file__), "holdout")
CASES_F = os.path.join(HOLD, "cases.json")
if not os.path.exists(CASES_F):
    pytest.skip("holdout সেট এখনো বানানো হয়নি (tests/build_holdout.py চালাও)",
                allow_module_level=True)

CASES = json.load(open(CASES_F, encoding="utf-8"))
RAW = pd.read_csv(os.path.join(HOLD, "real_events.csv"), dtype=str, keep_default_na=False)
MEDIUM = 40


@pytest.fixture(scope="module")
def scored():
    good, _ = ingest.normalize(RAW)
    return detect.score_events(good)


@pytest.mark.parametrize("c", CASES, ids=[c["id"] + "_" + c["ip"] for c in CASES])
def test_holdout_ip(scored, c):
    rows = scored[scored["ip"] == c["ip"]]
    assert len(rows), f"{c['ip']} scored ডেটায় নেই"
    top = int(rows["risk_score"].max())
    if c["label"] == "attack":
        assert top >= MEDIUM, f"{c['why']}: max score {top} (ধরা পড়েনি)"
    else:
        assert top < MEDIUM, f"{c['why']}: max score {top} (ভুয়া alert)"
# Writes the fake cloud's fixture from the platform's frozen surface transcript.
# Run as: python3 cloud_fixture.py <wapps-platform checkout> <out.json>
# Reads services/broker/test/frozen/surface-transcript.json (the 37 routes played
# through the real route table, frozen from the live Worker) and keeps, per HTTP
# case, what the fake serves: the request it answers and the answer's bytes.
# Dropped: the tables, alarm and ledger channels (the fake has no state), and the
# ALARM cases, which are Durable Object alarms and not requests.
import hashlib, json, subprocess, sys

platform, out = sys.argv[1], sys.argv[2]
rel = "services/broker/test/frozen/surface-transcript.json"
raw = open(f"{platform}/{rel}", "rb").read()
commit = subprocess.run(["git", "-C", platform, "log", "-1", "--format=%H", "--", rel],
                        capture_output=True, text=True, check=True).stdout.strip()
cases = json.loads(raw)
keep = ("id", "says", "route", "principal", "request", "status", "envelope", "body")
exchanges = [{k: c[k] for k in keep} for c in cases if c["route"] != "ALARM"]
fixture = {
    "provenance": {
        "source": f"wapps-platform/{rel}",
        "commit": commit,
        "sha256": hashlib.sha256(raw).hexdigest(),
        "cases": len(cases),
        "dropped_alarm_cases": len(cases) - len(exchanges),
    },
    "exchanges": exchanges,
}
with open(out, "w", encoding="utf-8") as f:
    json.dump(fixture, f, ensure_ascii=False, indent=1)
    f.write("\n")
print(f"{len(exchanges)} exchanges over {len({e['route'] for e in exchanges})} routes from {commit[:7]}")

"""Runs all experiments against a live OPA server; writes results/*.json and results/decisions.csv"""
import json, random, time, statistics as st, csv, copy, sys
sys.path.insert(0, "eval")
from model import decide, ground_truth, ACTIONS, W, TAU, THREAT_W, CONTROL_CREDIT
from opa_client import OPA

opa = OPA()
res = json.load(open("data/resources.json")); ctx = json.load(open("data/context.json"))
STEADY = {"threat_level": "normal", "operational_mode": "steady"}
rank = {a: i for i, a in enumerate(ACTIONS)}

# --- collect findings from OPA (policy evaluation is unchanged, deterministic) ---
findings = []
for r in res:
    for v in opa.violations(r):
        findings.append((r, v))
print("resources", len(res), "findings", len(findings), "resources w/ >=1 violation",
      len({r["name"] for r, _ in findings}))

def baseline(name, v, c):
    if name == "static": return "block"
    if name == "prod_only": return "block" if c["env"] == "prod" else "none"
    if name == "severity_tiered": return {"high": "block", "medium": "warn", "low": "advisory"}[v["severity"]]

def score(actions, gts):
    def n(cond): return sum(1 for a, g in zip(actions, gts) if cond(a, g))
    hi = sum(g == "High" for g in gts); me = sum(g == "Medium" for g in gts); lo = sum(g == "Low" for g in gts)
    interrupt = lambda a: a in ("approve", "block")
    attention = lambda a: a in ("warn", "approve", "block")
    return {"high_total": hi, "medium_total": me, "low_total": lo,
            "high_recall": n(lambda a, g: g == "High" and interrupt(a)),
            "medium_covered": n(lambda a, g: g == "Medium" and attention(a)),
            "low_interrupted": n(lambda a, g: g == "Low" and interrupt(a)),
            "low_blocked": n(lambda a, g: g == "Low" and a == "block"),
            "attention_items": n(lambda a, g: attention(a)),
            "hard_blocks": n(lambda a, g: a == "block"),
            "high_missed_entirely": n(lambda a, g: g == "High" and not attention(a))}

out = {}
gts = [ground_truth(v, ctx[r["name"]]) for r, v in findings]
rows = []
for name in ["static", "prod_only", "severity_tiered", "context_aware"]:
    acts = []
    for (r, v), g in zip(findings, gts):
        c = ctx[r["name"]]
        a = decide(v, c, STEADY)[0] if name == "context_aware" else baseline(name, v, c)
        acts.append(a)
        if name == "context_aware":
            rows.append([r["name"], r["kind"], v["policy"], v["severity"], c["env"], c["data_sensitivity"],
                         c["internet_facing"], c["compensating_control"], g, a, round(decide(v, c, STEADY)[1], 3)])
    out[name] = score(acts, gts)
with open("results/decisions.csv", "w", newline="") as f:
    w = csv.writer(f); w.writerow(["resource", "kind", "policy", "severity", "env", "data", "internet_facing",
                                   "compensating_control", "ground_truth", "decision", "risk"]); w.writerows(rows)
# confusion matrix for context-aware
conf = {g: {a: 0 for a in ACTIONS} for g in ("High", "Medium", "Low")}
for row in rows: conf[row[8]][row[9]] += 1
out["context_aware_confusion"] = conf
out["by_env_findings"] = {e: sum(1 for r, _ in findings if ctx[r["name"]]["env"] == e) for e in ("dev", "staging", "prod")}

# --- E2 incident response: 50 emergency prod deployments ---
random.seed(7)
inc_ctx = {"env": "prod", "data_sensitivity": "confidential", "internet_facing": True, "compensating_control": False}
emerg = []
for i in range(40):
    img = random.choice(["docker.io/vendor/hotfix:2.0.1", "registry.internal.example/svc:latest"])
    emerg.append({"kind": "Deployment", "metadata": {"tags": {"owner": "oncall", "cost-center": "cc-1"}},
                  "spec": {"exposure": "internal", "containers": [{"image": img, "limits": {"cpu": "1"}}]}})
for i in range(10):
    emerg.append({"kind": "Deployment", "metadata": {"tags": {"owner": "oncall", "cost-center": "cc-1"}},
                  "spec": {"exposure": "internal", "containers": [{"image": "registry.internal.example/debug:1", "limits": {"cpu": "1"}, "privileged": True}]}})
inc = {"threat_level": "normal", "operational_mode": "incident", "incident_ticket": "INC-0001"}
def deploy_outcome(r, gctx):
    acts = [decide(v, inc_ctx, gctx)[0] for v in opa.violations(r)]
    return max(acts, key=lambda a: rank[a])
e2 = {"static_blocked": 50}
for label, gctx in (("context_steady", STEADY), ("context_incident", inc)):
    o = [deploy_outcome(r, gctx) for r in emerg]
    e2[label] = {"deferrable_40": {a: o[:40].count(a) for a in ACTIONS}, "privileged_10": {a: o[40:].count(a) for a in ACTIONS}}
out["incident"] = e2

# --- E3 threat elevation ---
e3 = {}
for t in ("normal", "elevated", "critical"):
    acts = [decide(v, ctx[r["name"]], {"threat_level": t})[0] for r, v in findings]
    e3[t] = {a: acts.count(a) for a in ACTIONS}
out["threat"] = e3

# --- E4 missing context (15% of resources lose all context) ---
random.seed(11)
dropped = set(random.sample([r["name"] for r in res], int(.15 * len(res))))
acts = [decide(v, None if r["name"] in dropped else ctx[r["name"]], STEADY)[0] for r, v in findings]
out["missing_context"] = {"resources_dropped": len(dropped),
                          "findings_affected": sum(1 for r, _ in findings if r["name"] in dropped), **score(acts, gts)}

# --- E5 sensitivity: 1000 perturbations of weights (+/-30%) and thresholds (+/-0.05) ---
random.seed(3)
hr, li, at = [], [], []
for _ in range(1000):
    w = {k: v * random.uniform(.7, 1.3) for k, v in W.items()}
    s = sum(w.values()); w = {k: v / s for k, v in w.items()}
    tau = tuple(t + random.uniform(-.05, .05) for t in TAU)
    acts = [decide(v, ctx[r["name"]], STEADY, tau=tau, w=w)[0] for r, v in findings]
    sc = score(acts, gts)
    hr.append(sc["high_recall"] / sc["high_total"]); li.append(sc["low_interrupted"] / sc["low_total"]); at.append(sc["attention_items"])
q = lambda xs, p: sorted(xs)[int(p * (len(xs) - 1))]
out["sensitivity"] = {"high_recall": {"min": min(hr), "p5": q(hr, .05), "median": st.median(hr), "max": max(hr)},
                      "low_interrupt_rate": {"min": min(li), "median": st.median(li), "p95": q(li, .95), "max": max(li)},
                      "attention_items": {"min": min(at), "median": st.median(at), "max": max(at)}}

# --- E6 latency (OPA REST on localhost; context from in-memory cache) ---
for r in res[:200]: opa.violations(r)  # warm-up
s_lat, c_lat = [], []
for i in range(3000):
    r = res[i % len(res)]
    t0 = time.perf_counter(); opa.violations(r); s_lat.append((time.perf_counter() - t0) * 1000)
    t0 = time.perf_counter()
    c = ctx.get(r["name"]); vs = opa.violations(r); [decide(v, c, STEADY) for v in vs]
    c_lat.append((time.perf_counter() - t0) * 1000)
pct = lambda xs, p: sorted(xs)[int(p * (len(xs) - 1))]
out["latency_ms"] = {k: {"p50": round(pct(x, .5), 3), "p95": round(pct(x, .95), 3), "p99": round(pct(x, .99), 3)}
                     for k, x in (("static_opa", s_lat), ("context_aware", c_lat))}
json.dump(out, open("results/results.json", "w"), indent=1)
print(json.dumps(out, indent=1))

"""Additional experiments for the revised manuscript (reviewer responses).
Requires the same live OPA server as experiments.py. Writes results/revision_results.json.

E7  Block-only recall and imperfect approval (R1)
E8  Unified cost model and break-even analysis vs. severity-tiered (R2)
E9  Context-forgery attacks and mitigations; forged incident tickets; decision-service failure (R1, R2, R3)
E10 Wide parameter sensitivity with decision-flip rates (R2)
E11 Multiplicative (geometric-mean) impact x likelihood risk form (R3)
E12 Replication across 20 independently seeded datasets (R3)
E13 Latency with context fetched from a separate service on a cache miss (R3)
"""
import json, random, time, statistics as st, sys, os, copy, threading, http.server, http.client, tempfile
sys.path.insert(0, "eval")
import model
from model import decide, ground_truth, ACTIONS, W, TAU, SECURITY_CRITICAL, DEFERRABLE_IN_INCIDENT, FAILSAFE
from opa_client import OPA

opa = OPA()
RANK = {a: i for i, a in enumerate(ACTIONS)}
STEADY = {"threat_level": "normal", "operational_mode": "steady"}
OUT = {}

def collect(res):
    return [(r, v) for r in res for v in opa.violations(r)]

def baseline(name, v, c):
    if name == "static": return "block"
    if name == "prod_only": return "block" if c["env"] == "prod" else "none"
    if name == "severity_tiered": return {"high": "block", "medium": "warn", "low": "advisory"}[v["severity"]]

def actions_for(name, findings, ctx, **kw):
    if name == "context_aware":
        return [decide(v, ctx[r["name"]], STEADY, **kw)[0] for r, v in findings]
    return [baseline(name, v, ctx[r["name"]]) for r, v in findings]

def metrics(acts, gts):
    n = lambda f: sum(1 for a, g in zip(acts, gts) if f(a, g))
    tot = {g: gts.count(g) for g in ("High", "Medium", "Low")}
    return {"high_recall_approve_or_block": n(lambda a, g: g == "High" and a in ("approve", "block")),
            "high_recall_block_only": n(lambda a, g: g == "High" and a == "block"),
            "medium_covered": n(lambda a, g: g == "Medium" and a in ("warn", "approve", "block")),
            "low_interrupted": n(lambda a, g: g == "Low" and a in ("approve", "block")),
            "low_blocked": n(lambda a, g: g == "Low" and a == "block"),
            "hard_blocks": n(lambda a, g: a == "block"),
            "approvals": n(lambda a, g: a == "approve"),
            "warnings": n(lambda a, g: a == "warn"),
            "attention_items": n(lambda a, g: a in ("warn", "approve", "block")), **{f"{k}_total": v for k, v in tot.items()}}

def confusion(acts, gts):
    return {g: {a: sum(1 for x, y in zip(acts, gts) if y == g and x == a) for a in ACTIONS + ["none"]} for g in ("High", "Medium", "Low")}

res = json.load(open("data/resources.json")); ctx = json.load(open("data/context.json"))
F = collect(res)
GT = [ground_truth(v, ctx[r["name"]]) for r, v in F]
STRATS = ["static", "prod_only", "severity_tiered", "context_aware"]
ACTS = {s: actions_for(s, F, ctx) for s in STRATS}
assert len(F) == 403

# ---------------- E7 block-only recall + imperfect approval ----------------
e7 = {s: metrics(ACTS[s], GT) for s in STRATS}
e7["confusion"] = {s: confusion(ACTS[s], GT) for s in ("severity_tiered", "context_aware")}
# Approval treated as imperfect: an approver wrongly approves a High/Medium violation with probability q.
# Expected number of High-risk violations that reach deployment = (#High approved)*q + (#High warned/advised/none).
e7["expected_high_deployed"] = {s: {str(q): round(sum((q if a == "approve" else 0 if a == "block" else 1)
                                                      for a, g in zip(ACTS[s], GT) if g == "High"), 2)
                                    for q in (0.0, 0.05, 0.1, 0.25, 0.5)} for s in STRATS}
# the two High violations routed to approval: why
e7["high_approved_detail"] = [{"resource": r["name"], "policy": v["policy"], **ctx[r["name"]],
                               "R": round(decide(v, ctx[r["name"]], STEADY)[1], 3)}
                              for (r, v), g, a in zip(F, GT, ACTS["context_aware"]) if g == "High" and a == "approve"]
OUT["E7_recall"] = e7

# ---------------- E8 unified cost model ----------------
# Operational cost in units of one warning (c_warn = 1): c_approve = ka, c_block = kb.
# Residual-risk cost: a violation that reaches deployment costs L_g (L_Low = 0). Advisory/warn/none deploy;
# approval deploys with probability q for High/Medium (wrong approval); block never deploys.
def cost(acts, gts, ka, kb, q=0.1, LH=100.0, LM=10.0):
    op = sum({"warn": 1, "approve": ka, "block": kb}.get(a, 0) for a in acts)
    L = {"High": LH, "Medium": LM, "Low": 0.0}
    rr = sum(L[g] * (0 if a == "block" else q if a == "approve" else 1) for a, g in zip(acts, gts))
    return op, rr
cnt = {s: {a: ACTS[s].count(a) for a in ACTIONS + ["none"]} for s in STRATS}
ca, sv = cnt["context_aware"], cnt["severity_tiered"]
# Break-even (operational cost only): CA cheaper than ST iff
#   ca_w + ka*ca_a + kb*ca_b < sv_w + ka*sv_a + kb*sv_b
e8 = {"action_counts": cnt,
      "break_even": f"CA cheaper iff kb > ({ca['warn']-sv['warn']} + {ca['approve']-sv['approve']}*ka) / {sv['block']-ca['block']}"}
grid = []
for ka in (1, 2, 3, 5, 10):
    for kb in (1, 2, 3, 5, 10, 20):
        row = {"ka": ka, "kb": kb}
        for s in STRATS:
            op, rr = cost(ACTS[s], GT, ka, kb)
            row[s] = round(op + rr, 1); row[s + "_op"] = op; row[s + "_risk"] = round(rr, 1)
        row["best"] = min(STRATS, key=lambda s: row[s])
        grid.append(row)
e8["grid_q0.1_LH100_LM10"] = grid
e8["kb_breakeven_by_ka"] = {ka: round(((ca["warn"] - sv["warn"]) + (ca["approve"] - sv["approve"]) * ka) / (sv["block"] - ca["block"]), 2)
                            for ka in (1, 2, 3, 5, 10)}
# Residual-risk cost sensitivity: how large must LH be (q=0.1) before ST's extra 2 High blocks outweigh?
# Cost-optimal operating point: choose tau by minimizing total cost on half the resources, evaluate on the other half.
def tau_grid():
    for a in [x / 100 for x in range(20, 56, 5)]:
        for b in [x / 100 for x in range(30, 76, 5)]:
            for c in [x / 100 for x in range(50, 96, 5)]:
                if a < b < c: yield (a, b, c)
random.seed(5)
names = sorted({r["name"] for r in res}); random.shuffle(names); half = set(names[:300])
idxA = [i for i, (r, _) in enumerate(F) if r["name"] in half]; idxB = [i for i, (r, _) in enumerate(F) if r["name"] not in half]
def ca_acts(idx, tau): return [decide(F[i][1], ctx[F[i][0]["name"]], STEADY, tau=tau)[0] for i in idx]
opt = []
for ka, kb in ((2, 5), (3, 10), (5, 20)):
    best = min(tau_grid(), key=lambda t: sum(cost(ca_acts(idxA, t), [GT[i] for i in idxA], ka, kb)))
    accB = ca_acts(idxB, best); gtB = [GT[i] for i in idxB]
    defB = ca_acts(idxB, TAU); stB = [ACTS["severity_tiered"][i] for i in idxB]
    opt.append({"ka": ka, "kb": kb, "tau_opt_on_A": best,
                "test_B_cost": {"ca_opt": round(sum(cost(accB, gtB, ka, kb)), 1), "ca_default": round(sum(cost(defB, gtB, ka, kb)), 1),
                                "severity_tiered": round(sum(cost(stB, gtB, ka, kb)), 1)},
                "test_B_metrics_opt": metrics(accB, gtB), "test_B_metrics_default": metrics(defB, gtB)})
e8["cost_optimal_tau_holdout"] = opt
OUT["E8_cost"] = e8

# ---------------- E9 context forgery ----------------
def forge(c, kind):
    c = dict(c)
    if kind in ("env", "all"): c["env"] = "dev"
    if kind in ("data", "all"): c["data_sensitivity"] = "public"
    if kind in ("exposure", "all"): c["internet_facing"] = False
    if kind in ("control", "all"): c["compensating_control"] = True
    return c

def observable_exposure(r):  # attribute observable from the submitted spec itself
    return r["spec"].get("exposure") == "public"

def mitigate(r, claimed, inventory):
    """Mitigation M: (i) attributes taken as the stricter of the submitter's claim and the authenticated
    inventory record; (ii) exposure cannot be claimed lower than what the spec itself shows;
    (iii) compensating-control credit only if recorded in the inventory."""
    o = {}
    o["env"] = max(claimed["env"], inventory["env"], key=lambda e: model.R_ENV[e])
    o["data_sensitivity"] = max(claimed["data_sensitivity"], inventory["data_sensitivity"], key=lambda d: model.R_DATA[d])
    o["internet_facing"] = claimed["internet_facing"] or inventory["internet_facing"] or observable_exposure(r)
    o["compensating_control"] = claimed["compensating_control"] and inventory["compensating_control"]
    return o

def stale(c, s, rng):
    """Inventory record that is wrong with probability s per attribute (random other value)."""
    c = dict(c)
    if rng.random() < s: c["env"] = rng.choice([e for e in model.R_ENV if e != c["env"]])
    if rng.random() < s: c["data_sensitivity"] = rng.choice([d for d in model.R_DATA if d != c["data_sensitivity"]])
    if rng.random() < s: c["internet_facing"] = not c["internet_facing"]
    if rng.random() < s: c["compensating_control"] = not c["compensating_control"]
    return c

e9 = {"attacks": {}}
for frac in (0.1, 0.25, 1.0):
    for kind in ("env", "data", "exposure", "control", "all"):
        rng = random.Random(13)
        forged = set(rng.sample(names, int(frac * len(names))))
        out_rows = {}
        for label in ("no_mitigation", "mitigation_fresh_inventory", "mitigation_10pct_stale_inventory"):
            rng2 = random.Random(17)
            inv = {n: (stale(ctx[n], .10, rng2) if "stale" in label else ctx[n]) for n in names}
            acts = []
            for r, v in F:
                c = ctx[r["name"]]
                claimed = forge(c, kind) if r["name"] in forged else c
                used = claimed if label == "no_mitigation" else mitigate(r, claimed, inv[r["name"]])
                acts.append(decide(v, used, STEADY)[0])
            m = metrics(acts, GT)
            out_rows[label] = {"high_recall_approve_or_block": m["high_recall_approve_or_block"],
                               "high_recall_block_only": m["high_recall_block_only"],
                               "high_downgraded_to_warn_or_less": sum(1 for a, g in zip(acts, GT) if g == "High" and a in ("advisory", "warn")),
                               "medium_covered": m["medium_covered"], "hard_blocks": m["hard_blocks"],
                               "low_interrupted": m["low_interrupted"], "attention_items": m["attention_items"]}
        e9["attacks"][f"{kind}@{int(frac*100)}%"] = out_rows
# cost of the mitigation with no attack (legit traffic, stale inventory forces stricter decisions)
rng2 = random.Random(17)
inv = {n: stale(ctx[n], .10, rng2) for n in names}
acts = [decide(v, mitigate(r, ctx[r["name"]], inv[r["name"]]), STEADY)[0] for r, v in F]
e9["mitigation_no_attack_10pct_stale"] = metrics(acts, GT)
# forged incident ticket: worst case = every deferrable block becomes approval; security-critical untouched
inc = {"threat_level": "normal", "operational_mode": "incident", "incident_ticket": "FORGED"}
acts_inc = [decide(v, ctx[r["name"]], inc)[0] for r, v in F]
e9["forged_incident_ticket"] = {"steady": metrics(ACTS["context_aware"], GT), "forged_ticket": metrics(acts_inc, GT),
                                "security_critical_blocks_steady": sum(1 for (r, v), a in zip(F, ACTS["context_aware"]) if v["policy"] in SECURITY_CRITICAL and a == "block"),
                                "security_critical_blocks_forged": sum(1 for (r, v), a in zip(F, acts_inc) if v["policy"] in SECURITY_CRITICAL and a == "block")}
# decision-service failure: fall back to severity-tiered static mapping (fail-closed for High severity)
e9["decision_service_failure_fallback_severity_tiered"] = metrics(ACTS["severity_tiered"], GT)
OUT["E9_forgery"] = e9

# ---------------- E10 wide sensitivity with decision-flip rates ----------------
base = ACTS["context_aware"]
def sample_narrow(rng):
    w = {k: v * rng.uniform(.7, 1.3) for k, v in W.items()}; s = sum(w.values())
    return {k: v / s for k, v in w.items()}, tuple(t + rng.uniform(-.05, .05) for t in TAU)
def sample_wide(rng):
    g = {k: rng.gammavariate(1, 1) for k in W}; s = sum(g.values())   # uniform on the weight simplex
    t1 = rng.uniform(.20, .50); t2 = rng.uniform(t1 + .05, .70); t3 = rng.uniform(t2 + .05, .90)
    return {k: v / s for k, v in g.items()}, (t1, t2, t3)
e10 = {}
for label, sampler in (("narrow_pm30pct", sample_narrow), ("wide_simplex", sample_wide)):
    rng = random.Random(3); flips, hr, hb, li, hbk, att, sev_flip = [], [], [], [], [], [], []
    for _ in range(1000):
        w, tau = sampler(rng)
        acts = [decide(v, ctx[r["name"]], STEADY, tau=tau, w=w)[0] for r, v in F]
        m = metrics(acts, GT)
        flips.append(sum(a != b for a, b in zip(acts, base)) / len(base))
        sev_flip.append(sum(abs(RANK[a] - RANK[b]) >= 2 for a, b in zip(acts, base)) / len(base))
        hr.append(m["high_recall_approve_or_block"]); hb.append(m["high_recall_block_only"])
        li.append(m["low_interrupted"]); hbk.append(m["hard_blocks"]); att.append(m["attention_items"])
    q = lambda xs, p: sorted(xs)[int(p * (len(xs) - 1))]
    summ = lambda xs: {"min": min(xs), "p5": q(xs, .05), "median": st.median(xs), "p95": q(xs, .95), "max": max(xs)}
    e10[label] = {"decision_flip_rate": summ(flips), "two_level_flip_rate": summ(sev_flip),
                  "high_recall_approve_or_block": summ(hr), "high_recall_block_only": summ(hb),
                  "runs_high_recall_below_26": sum(x < 26 for x in hr),
                  "low_interrupted": summ(li), "hard_blocks": summ(hbk), "attention_items": summ(att)}
# Admissibility: enumerate EVERY context (not just the sampled dataset) whose ground truth is High,
# and find the minimum risk score the model can assign to it. If tau_approve <= R_min, every possible
# High-risk violation is routed to approval or block; if tau_block <= R_min, every one is blocked.
import itertools
def enum_high():
    for p, sev in (("P1_encryption_at_rest", "high"), ("P2_public_exposure", "high"), ("P5_privileged", "high"),
                   ("P3_image_registry", "medium"), ("P7_latest_tag", "medium"), ("P4_resource_limits", "low"), ("P6_required_tags", "low")):
        for env, d, inet, ctl in itertools.product(model.R_ENV, model.R_DATA, (True, False), (True, False)):
            c = {"env": env, "data_sensitivity": d, "internet_facing": inet, "compensating_control": ctl}
            v = {"policy": p, "severity": sev}
            if ground_truth(v, c) == "High": yield v, c
HIGH_SPACE = list(enum_high())
def r_min(w=W): return min(model.risk(v["severity"], c, w=w) for v, c in HIGH_SPACE)
argmin = min(HIGH_SPACE, key=lambda vc: model.risk(vc[0]["severity"], vc[1]))
e10["admissibility"] = {"high_risk_context_space": len(HIGH_SPACE), "R_min_default": round(r_min(), 3),
                        "tau_approve": TAU[1], "tau_block": TAU[2], "argmin_context": {**argmin[1], "policy": argmin[0]["policy"]},
                        "guarantee_approve_or_block": r_min() >= TAU[1], "guarantee_block": r_min() >= TAU[2]}
rng = random.Random(3); adm = fail_adm = fail_nonadm = 0
for _ in range(1000):
    w, tau = sample_wide(rng)
    ok = r_min(w) >= tau[1]
    acts = [decide(v, ctx[r["name"]], STEADY, tau=tau, w=w)[0] for r, v in F]
    full = metrics(acts, GT)["high_recall_approve_or_block"] == 26
    adm += ok; fail_adm += ok and not full; fail_nonadm += (not ok) and not full
e10["wide_simplex"]["admissible_runs"] = adm
e10["wide_simplex"]["recall_failures_among_admissible"] = fail_adm
e10["wide_simplex"]["recall_failures_among_inadmissible"] = fail_nonadm
OUT["E10_sensitivity"] = e10

# ---------------- E11 multiplicative risk form ----------------
def risk_geo(sev, c, threat="normal"):
    imp = .5 * model.R_SEV[sev] + .5 * model.R_DATA[c["data_sensitivity"]]
    like = .5 * model.R_ENV[c["env"]] + .5 * (1.0 if c["internet_facing"] else .3)
    like = min(1.0, like + model.THREAT_W * model.R_THREAT[threat])
    if c["compensating_control"]: like = max(0.0, like - model.CONTROL_CREDIT)
    return (imp * like) ** .5
def decide_geo(v, c, tau=TAU):
    R = risk_geo(v["severity"], c)
    return "advisory" if R < tau[0] else "warn" if R < tau[1] else "approve" if R < tau[2] else "block"
acts_geo = [decide_geo(v, ctx[r["name"]]) for r, v in F]
hyg = lambda acts: sum(1 for (r, v), a, g in zip(F, acts, GT) if g == "Low" and v["policy"] in ("P4_resource_limits", "P6_required_tags") and a in ("approve", "block"))
OUT["E11_multiplicative"] = {"additive": {**metrics(base, GT), "low_hygiene_interrupted": hyg(base)},
                             "geometric_mean": {**metrics(acts_geo, GT), "low_hygiene_interrupted": hyg(acts_geo)},
                             "confusion_geometric": confusion(acts_geo, GT)}

# ---------------- E12 replication across seeds ----------------
src = open("eval/generate.py").read()
rep = {s: [] for s in STRATS + ["context_aware_geo"]}
nfind = []
for seed in range(1, 21):
    d = tempfile.mkdtemp()
    code = src.replace("random.seed(42)", f"random.seed({seed})").replace('"data/resources.json"', f'"{d}/r.json"').replace('"data/context.json"', f'"{d}/c.json"')
    exec(compile(code, "gen", "exec"), {"__name__": "gen", "print": lambda *a, **k: None})
    rs = json.load(open(f"{d}/r.json")); cx = json.load(open(f"{d}/c.json"))
    f = collect(rs); g = [ground_truth(v, cx[r["name"]]) for r, v in f]; nfind.append(len(f))
    for s in STRATS: rep[s].append(metrics(actions_for(s, f, cx), g))
    rep["context_aware_geo"].append(metrics([decide_geo(v, cx[r["name"]]) for r, v in f], g))
def agg(ms):
    keys = ["High_total", "high_recall_approve_or_block", "high_recall_block_only", "Medium_total", "medium_covered",
            "low_interrupted", "low_blocked", "hard_blocks", "attention_items"]
    return {k: {"mean": round(st.mean(m[k] for m in ms), 1), "sd": round(st.pstdev(m[k] for m in ms), 1),
                "min": min(m[k] for m in ms), "max": max(m[k] for m in ms)} for k in keys}
OUT["E12_replication_20_seeds"] = {"findings": {"mean": st.mean(nfind), "min": min(nfind), "max": max(nfind)},
                                   "high_recall_full_in_all_seeds": {s: all(m["high_recall_approve_or_block"] == m["High_total"] for m in rep[s]) for s in rep},
                                   **{s: agg(rep[s]) for s in rep}}

# ---------------- E13 latency with remote context service ----------------
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(ctx.get(self.path.strip("/"), {})).encode()
        self.send_response(200); self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self, *a): pass
srv = http.server.ThreadingHTTPServer(("127.0.0.1", 8282), H); threading.Thread(target=srv.serve_forever, daemon=True).start()
cconn = http.client.HTTPConnection("127.0.0.1", 8282)
def fetch(n):
    cconn.request("GET", "/" + n); return json.loads(cconn.getresponse().read())
for r in res[:200]: opa.violations(r); fetch(r["name"])
lat = {"opa_only": [], "cached_context": [], "remote_context_miss": []}
for i in range(3000):
    r = res[i % len(res)]
    t0 = time.perf_counter(); opa.violations(r); lat["opa_only"].append((time.perf_counter() - t0) * 1e3)
    t0 = time.perf_counter(); c = ctx[r["name"]]; [decide(v, c, STEADY) for v in opa.violations(r)]; lat["cached_context"].append((time.perf_counter() - t0) * 1e3)
    t0 = time.perf_counter(); c = fetch(r["name"]); [decide(v, c, STEADY) for v in opa.violations(r)]; lat["remote_context_miss"].append((time.perf_counter() - t0) * 1e3)
pct = lambda xs, p: round(sorted(xs)[int(p * (len(xs) - 1))], 3)
OUT["E13_latency_ms"] = {k: {"p50": pct(x, .5), "p95": pct(x, .95), "p99": pct(x, .99)} for k, x in lat.items()}
OUT["E13_latency_ms"]["note"] = "context service is a separate HTTP server on localhost; cross-host fetches add network RTT"
srv.shutdown()

json.dump(OUT, open("results/revision_results.json", "w"), indent=1, default=str)
print(json.dumps(OUT, indent=1, default=str))

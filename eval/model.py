"""Context-aware decision layer (D = f(P, C, R)) and independent ground-truth rubric.
Weights and thresholds are fixed a priori in this file and were NOT tuned on the
evaluation data; robustness to them is tested separately in experiments.py."""
SECURITY_CRITICAL = {"P1_encryption_at_rest", "P2_public_exposure", "P5_privileged"}
DEFERRABLE_IN_INCIDENT = {"P3_image_registry", "P4_resource_limits", "P6_required_tags", "P7_latest_tag"}
ACTIONS = ["advisory", "warn", "approve", "block"]          # ordered by stringency

R_ENV  = {"dev": .1, "staging": .4, "prod": 1.0}
R_DATA = {"public": .1, "internal": .4, "confidential": .8, "restricted": 1.0}
R_SEV  = {"low": .2, "medium": .5, "high": 1.0}
R_THREAT = {"normal": 0.0, "elevated": .5, "critical": 1.0}
W = {"env": .25, "data": .30, "sev": .25, "exposure": .20}
THREAT_W, CONTROL_CREDIT = .15, .15
TAU = (.35, .55, .75)
FAILSAFE = {"env": "prod", "data_sensitivity": "restricted", "internet_facing": True, "compensating_control": False}

def risk(sev, c, threat="normal", w=W, threat_w=THREAT_W, credit=CONTROL_CREDIT):
    r = (w["env"] * R_ENV[c["env"]] + w["data"] * R_DATA[c["data_sensitivity"]]
         + w["sev"] * R_SEV[sev] + w["exposure"] * (1.0 if c["internet_facing"] else .3))
    r += threat_w * R_THREAT[threat]
    if c["compensating_control"]: r -= credit
    return max(0.0, min(1.0, r))

def decide(violation, c, gctx, tau=TAU, **kw):
    """Returns (action, R, rationale). Missing context -> fail-safe defaults."""
    missing = c is None
    c = FAILSAFE if missing else c
    R = risk(violation["severity"], c, gctx.get("threat_level", "normal"), **kw)
    a = "advisory" if R < tau[0] else "warn" if R < tau[1] else "approve" if R < tau[2] else "block"
    why = [f"R={R:.2f}", f"env={c['env']}", f"data={c['data_sensitivity']}"]
    if missing: why.append("context missing: fail-safe defaults")
    if (gctx.get("operational_mode") == "incident" and gctx.get("incident_ticket")
            and violation["policy"] in DEFERRABLE_IN_INCIDENT and a == "block"):
        a = "approve"; why.append("incident mode: emergency approval path")
    return a, R, "; ".join(why)

# ---- Independent ground truth: NIST SP 800-30 (2002) qualitative risk matrix ----
IMPACT = {"H": 100, "M": 50, "L": 10}
LIKE = {"H": 1.0, "M": .5, "L": .1}
def ground_truth(violation, c):
    p, d = violation["policy"], c["data_sensitivity"]
    if p in SECURITY_CRITICAL and d in ("confidential", "restricted"): imp = "H"
    elif p in SECURITY_CRITICAL or (violation["severity"] == "medium" and d in ("confidential", "restricted")): imp = "M"
    else: imp = "L"
    like = "H" if (c["internet_facing"] or c["env"] == "prod") else "M" if c["env"] == "staging" else "L"
    if c["compensating_control"]: like = {"H": "M", "M": "L", "L": "L"}[like]   # controls reduce likelihood
    score = IMPACT[imp] * LIKE[like]
    return "High" if score > 50 else "Medium" if score > 10 else "Low"

# context-aware-pac

Reference implementation and evaluation for *Context-Aware Policy-as-Code: Risk-Proportional
Enforcement for Cloud Infrastructure Governance* (Manvitha Potluri, 24X7 Systems Inc.).

An unmodified Open Policy Agent (OPA) engine evaluates a single, context-free policy set
(`policies/normative.rego`). A separate decision layer (`eval/model.py`) combines each violation
with context (environment, data sensitivity, exposure, compensating controls, threat level,
operational mode) and a risk score to choose advisory / warn / approve / block.

## Reproduce
```bash
# OPA 0.68: https://github.com/open-policy-agent/opa/releases/tag/v0.68.0
opa test policies -v                       # 5/5 policy unit tests
python3 eval/generate.py                   # seeded synthetic dataset (600 resources)
opa run --server --addr 127.0.0.1:8181 policies/normative.rego &
python3 eval/experiments.py                # writes results/results.json and results/decisions.csv
```
No third-party Python packages are required.

## Scope and limitations
- Data are synthetic (seeded generator), not production inventories.
- Ground truth uses the NIST SP 800-30 qualitative risk matrix as defined in `eval/model.py`;
  it is author-defined and shares input attributes with the model.
- Model weights and thresholds were fixed a priori, not tuned; `experiments.py` includes a
  1,000-run sensitivity analysis.
- Latency is measured against OPA on localhost with context served from memory.

## License
Apache 2.0

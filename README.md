# NetTwin — Adversarial Network Configuration Verification

A reproducible research-oriented laboratory for **policy-model** verification, configuration mutation, counterfactual diagnosis and bounded repair. Includes a working dashboard, REST API and CLI. The portable model is **not** an executable network digital twin or proof of physical network security.

## Quick start (Windows PowerShell / macOS / Linux)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -e ".[web,test]"
python -m pytest -q
python -m nettwin.cli verify
python -m nettwin.cli verify --scenario benchmarks/faulty_guest_isolation.json
python -m nettwin.cli diagnose --scenario benchmarks/faulty_guest_isolation.json
python -m nettwin.cli repair --scenario benchmarks/faulty_guest_isolation.json
python -m nettwin.cli mutate
python -m streamlit run dashboard.py
```

On Linux/macOS activate with `source .venv/bin/activate` instead. If PowerShell blocks activation, run `.venv\Scripts\python.exe` directly.

REST API: `python -m uvicorn nettwin.api:app --reload`, then open `http://127.0.0.1:8000/docs`.

## What works

- Typed JSON scenario and ordered first-match ACL model
- Independent expected-flow assertions
- Deterministic policy-model verification and matched-rule evidence
- Seven mutation operator types, labelled by observable assertion changes
- Counterfactual deletion-based localization
- Bounded single-edit repair with full assertion recheck
- Repeatable probe-budget comparison (illustrative, limited assertion coverage)
- Streamlit dashboard, FastAPI endpoints, pytest suite, CLI

## Scientific limitations

1. **This release models ACL decisions. It does not transmit packets, run network namespaces, emulate routers, or test vendor devices.** The backend field explicitly reports `policy-model`.
2. A successful assertion suite is evidence for the enumerated flows only; it is not a security guarantee.
3. Mutation equivalence is measured only on listed assertions, not over the full packet space.
4. Mutation detection recall is tautologically 100% when the same assertions define both confirmation and detection. It is a software sanity check, **not a valid research performance estimate**. A credible study needs independent ground truth and held-out probes.
5. The probe strategy comparison counts only probes with known assertions and should not be presented as an empirical superiority claim.
6. Repair is a restricted deterministic search; it is not an LLM repair system.
7. LLM generation, Linux packet-level verification, real-device evaluation and externally validated benchmark results remain future work.

## Next research milestones

- Linux namespace backend with veth pairs, nftables deployment, socket-level probes and verified service health
- Held-out policy oracle and independent mutation-ground-truth labelling
- LLM structured intent parser with user-approved policy assertions
- Realistic multi-topology benchmark and fair equal-budget adversarial baselines
- Paired statistical evaluation with documented threats to validity

## Safety

Run generated configurations only in isolated environments. Do not apply model-generated firewall changes to your host or production devices.

## License

MIT. See LICENSE.

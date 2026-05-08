# MLOps Security Benchmark

A pipeline-stage threat model and control checklist for ML systems. Maps four
published frameworks (OWASP ML Top 10, OWASP LLM Top 10, MITRE ATLAS, NIST AI
RMF) onto seven concrete pipeline stages so engineers can put the right control
at the right stage.

## The seven stages

1. **Ingestion**: pulling data from sources (APIs, warehouses, change data capture)
2. **Versioning**: DVC, Git LFS, or object-store snapshots of data and code
3. **Training**: model fit, hyperparameter tuning, evaluation
4. **Registry**: where artifacts live before deployment
5. **Serving**: inference API, container, autoscaling
6. **Monitoring**: drift, fairness, performance telemetry
7. **LLM/Generative overlay**: prompt management, guardrails, RAG

Stages 1–6 apply to every pipeline. Stage 7 is an overlay that adds new threats
on top of the existing six.

## Threat × stage matrix

`P` = primary control point, `S` = secondary, blank = not applicable.

| Threat                                | Ingest | Version | Train | Reg | Serve | Monitor | LLM |
|---------------------------------------|:------:|:-------:|:-----:|:---:|:-----:|:-------:|:---:|
| Data poisoning (OWASP ML02)           |   P    |    S    |       |     |       |    S    |     |
| Label flipping (MITRE ATLAS)          |   P    |    S    |       |     |       |    S    |     |
| Supply chain compromise               |        |    S    |   P   |  S  |   S   |         |     |
| Model file tampering                  |        |         |       |  P  |   S   |         |     |
| Adversarial inputs (OWASP ML01)       |        |         |   S   |     |   P   |    S    |     |
| Model inversion                       |        |         |   P   |     |   S   |         |     |
| Membership inference                  |        |         |   P   |     |   S   |         |     |
| Model extraction (theft via API)      |        |         |       |     |   P   |    S    |     |
| Drift used as cover for attack        |        |         |       |     |       |    P    |     |
| Prompt injection (OWASP LLM01)        |        |         |       |     |   S   |         |  P  |
| Sensitive info disclosure (LLM02)     |        |         |       |     |       |    S    |  P  |
| Excessive agency (LLM06)              |        |         |       |     |       |         |  P  |
| Vector store poisoning (RAG)          |   P    |    S    |       |     |       |         |  P  |

## Per-stage controls

### 1. Ingestion

- [ ] Source authentication (signed feeds, mTLS, IAM)
- [ ] Schema contract enforcement (Great Expectations, Pandera)
- [ ] Class-balance regression test
- [ ] Outlier rate ceiling with quarantine path
- [ ] PII scanner before landing (Google DLP API, Presidio)

### 2. Versioning

- [ ] Signed Git commits (gitsign, GPG)
- [ ] DVC remote with object lock or generation match
- [ ] Hash-pinned Python deps (`pip-compile --generate-hashes`)
- [ ] Forensic audit trail (`dvc log` plus GitHub audit log retention)

### 3. Training

- [ ] Hermetic training runs (Docker, fixed base image SHA)
- [ ] Differential privacy where membership inference matters (Opacus, TF Privacy)
- [ ] Robust training for adversarial examples on high-risk models
- [ ] Training run identity (signed by service account)
- [ ] Lineage logged to MLflow (one model = one git SHA + one DVC hash + one container digest)

### 4. Registry

- [ ] Signed model artifacts (cosign, sigstore)
- [ ] SBOM attached to artifact
- [ ] Model card with security metadata (DP epsilon, training data version, fairness audit, known limitations)
- [ ] Promotion gate from staging to prod (explicit human approval)
- [ ] Immutable tags (no `latest` in prod)

### 5. Serving

- [ ] Authenticated endpoint
- [ ] Rate limiting per principal
- [ ] Input schema validation
- [ ] Output filtering for PII
- [ ] Resource limits, readiness/liveness probes
- [ ] Watermarking for extraction defense
- [ ] Container scanning in CI (Trivy, Grype)
- [ ] Least-privilege service accounts (no `Editor` role)

### 6. Monitoring

- [ ] Drift detection wired as a security signal (alerts SRE, not just MLE)
- [ ] Right test for the data shape (KS for continuous, Chi-squared for categorical, MMD for embeddings)
- [ ] Fairness monitoring on production traffic (sliding window)
- [ ] Audit logging with PII redacted, retention aligned with GDPR / DPDPA / nFADP
- [ ] Anomaly detection on request patterns

### 7. LLM / Generative overlay

- [ ] Input guardrail before the model (regex blocklist + structural Pydantic check)
- [ ] Output guardrail after the model (canary token leakage scan + format validator)
- [ ] Prompt versioning under git (every change is a PR with diff review)
- [ ] Critique LLM as an optional second pass for high-risk decisions
- [ ] Per-tenant rate limits
- [ ] Tracing with cost capture (MLflow 3.x traces, cost-per-tenant dashboard)

## Scoring guide

Score each stage 0–10 by counting verified controls divided by total
applicable controls, scaled. Two recommended cuts:

- **≥ 7/10 across every applicable stage** → "I'd let it serve real traffic."
- **≥ 5/10 with no stage below 3** → internal demo or research deployment.

A passing score means the obvious controls are in place. It does not mean
you're safe against a determined attacker. For high-risk deployments
(medical, financial, identity verification), pair this with a formal red-team
engagement.

## What this benchmark is not

It isn't a replacement for SOC 2, HIPAA, or nFADP. Those still apply.
The benchmark sits above them.

It isn't static. OWASP ML Top 10 and OWASP LLM Top 10 are revised every year.
The threat × stage matrix should be regenerated as new threats land.

It isn't a guarantee.

## License

MIT.

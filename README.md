# mlops-security-benchmark

A pipeline-stage threat model and control checklist for ML systems.

The published security frameworks (OWASP ML Top 10, OWASP LLM Top 10, MITRE
ATLAS, NIST AI RMF) tell you *what* can go wrong. They don't tell you *where
in your pipeline* to put the control. This repo does that mapping for seven
concrete stages, plus reference implementations of the harder controls.

## Contents

```
security_benchmark.md           Standalone checklist (the document)
figures/
  pipeline_attack_surface.png   Pipeline diagram + attacker entry points
  threat_matrix.png             Primary threats per stage
  *.mmd                         Mermaid sources, regenerate with mmdc
reference/
  input_guard.py                Pydantic + regex prompt-injection blocker
  output_guard.py               Canary + shingle leakage scan
  drift_detection.py            KS / Chi-squared drift report
  redteam_runner.py             CI regression gate harness
  k8s/deployment.yaml           Hardened GKE deployment manifest
```

## Use

1. Open `security_benchmark.md` and walk through each stage's checklist
   against your pipeline.
2. Score each stage 0–10. The guide at the end of the checklist sets two cuts.
3. Drop the relevant scripts in `reference/` into your repo and adapt them to
   your domain. Each one is self-contained.

## Regenerate figures

```
mmdc -i figures/pipeline_attack_surface.mmd -o figures/pipeline_attack_surface.png -w 1600 -H 900 -b white
mmdc -i figures/threat_matrix.mmd          -o figures/threat_matrix.png          -w 1600 -H 1100 -b white
```

## License

MIT.

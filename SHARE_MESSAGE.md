# Discourse / email message templates

Two short messages for sharing the post and the standalone checklist with the course team. Pick whichever channel fits.

---

## Option A: Discourse post (~130 words)

**Title:** Sharing a side project: pipeline-stage MLOps security benchmark + Medium write-up

While going through the course material, one thing kept coming up that the curriculum touches but doesn't consolidate: a single pipeline-stage threat model that maps published frameworks (OWASP ML Top 10, OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF) onto the actual stages of an ML pipeline.

I put together a checklist and scored two of my own builds against it (a heart disease classifier on GKE, and a small Vertex AI guardrails project). Wrote it up as a Medium post too.

- Standalone checklist: https://github.com/error9098x/mlops-security-benchmark/blob/main/security_benchmark.md
- Repo with reference scripts: https://github.com/error9098x/mlops-security-benchmark
- Medium post: https://medium.com/@error9098x/<post-slug>

If anyone has thoughts on what's missing or scored wrong, I'd like to hear.

---

## Option B: Email to the course team (~110 words)

**Subject:** MLOps security benchmark — sharing a write-up

Hi [Professor / TA name],

While working through the course I started consolidating the security material from Week 8 and Week 11 into a single pipeline-stage threat model. The framework maps OWASP ML Top 10, OWASP LLM Top 10, MITRE ATLAS, and NIST AI RMF onto seven concrete stages. I scored two of my own builds against it (heart disease classifier on GKE, and a Vertex AI guardrails project) to check it's useful in practice.

Sharing in case it's useful as reference material:

- Checklist: https://github.com/error9098x/mlops-security-benchmark/blob/main/security_benchmark.md
- Medium write-up: https://medium.com/@error9098x/<post-slug>

Happy to take any feedback.

Aviral

---

## Replace before sending

- `<post-slug>` in both messages — fill in once you've published the Medium post
- `[Professor / TA name]` in Option B — fill in the addressee
- Verify both GitHub links resolve in an incognito window before sending

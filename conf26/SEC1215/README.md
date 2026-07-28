# From Zero to Agentic: Building Your First AI-Driven Threat Investigation in Splunk Enterprise Security

**Event:** Splunk .Conf26  
**Date:** Tuesday, Sep 15 1:30 PM - 1:50 PM MDT
**Speaker:** David Pollard, Unshakeable Salt Ltd
**Session ID:** SEC1215

**Session Format:** Theater Session
**Track:** Security
**Skill Level:** Novice
**Primary Product or Service:** Splunk® Enterprise Security
**Other Product or Service:** Splunk Enterprise Security Premier, Detection Studio (integrated in Splunk ES Essentials)
**Industries:** Not industry specific, Federal Government, State & Local Government
**Role:** Security Architect/Engineer, Detection Engineer, Security Analyst/Manager
**Takeaway 1:** Choose the right LLM for SecOps — balancing cost, latency, privacy, and capability without defaulting to the biggest name.
**Takeaway 2:** A repeatable pattern to integrate agentic workflows into Splunk ES — what to build yourself vs. what Splunk gives you for free.
**Takeaway 3:** Avoid the top pitfalls — a prioritised starting framework for teams with limited time and budget to reach value fast.

_(Corrected from a copy/paste mismatch with SEC1053 — see [SEC1215.md](./SEC1215.md) for the source-of-truth submission text.)_

## Abstract

Agentic AI promises autonomous security operations — but where do you actually start? This session cuts through the hype with hard-won lessons from building a bespoke agentic use case inside Splunk Enterprise Security from scratch. We cover LLM selection on a real-world budget, native Splunk integration patterns, and the critical pitfalls that cost time before delivering value. Practical, honest, and immediately applicable.

## Talk Narrative: Closing the Agentic Loop

The demo/architecture story for this session, written up in full in [`ARCHITECTURE.md`](./ARCHITECTURE.md):

1. **ES alert-action output feeds the agentic AI** — shipped via [`TA_ResponseActions`](../TA_ResponseActions/README.md): a notable's full CIM/risk JSON, plus a standing `perplexity_ask` block of checks, delivered to Slack.
2. **The AI answers, in-line, before delivery** — a synchronous call to the Perplexity API, made inside the same alert action, with a JSON Schema `response_format` so the answer is already structured — no separate parsing step, no waiting on a chat reply.
3. **The same payload flows into every existing write-back path** — Slack (for visual audit), the originating notable's comment trail, and the KV store enrichment record — one process, no polling, no bridge.

An earlier design used an asynchronous Slack → HEC bridge for steps 2–3 instead; it shipped, worked, and was deliberately retired once its operational cost became clear. See [`lessons/`](./lessons/README.md) for that write-up, kept as a concrete Takeaway 3 example.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full diagram and how each phase ties back to Takeaways 1–3.

## Contents

| File / Folder | Description |
|---|---|
| `ARCHITECTURE.md` | The agentic loop narrative behind this talk |
| `lessons/` | Retired designs kept as documented "before" artifacts — the hourly-cron HEC recreate-prompt and the Slack → HEC bridge — see [`lessons/README.md`](./lessons/README.md) |
| `slides/` | Presentation source, one Markdown file per slide (`01-title.md` … `15-thank-you-resources.md`), each with a `## Speakers Notes` section |
| `demos/` | Demo scripts and supporting code |
| `images/` | Diagrams and screenshots |

## Prerequisites

_List any prerequisites needed to run the demos (e.g., Splunk version, Python version, required Add-ons)._

## Running the Demos

_Provide step-by-step instructions for running each demo._

## Resources

- [Splunk Documentation](https://docs.splunk.com)
- [Session recording](#) _(link when available)_

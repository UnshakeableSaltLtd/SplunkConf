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

## Talk Narrative: The Three-Phase Agentic Loop

The demo/architecture story for this session is a three-phase loop, written up in full in [`ARCHITECTURE.md`](./ARCHITECTURE.md):

1. **ES alert-action output feeds the agentic AI** — shipped today via [`TA_ResponseActions`](../TA_ResponseActions/README.md): a notable's full CIM/risk JSON, plus a standing `perplexity_ask` block of checks, delivered to Slack.
2. **The AI's answer becomes a CIM-compliant event** — the planned Slack → HEC bridge maps the agentic AI's verdict onto CIM Risk data model fields (`risk_object`, `risk_object_type`, `risk_score`, `risk_message`) instead of leaving it as unstructured chat text.
3. **Splunk's own APIs place it for the SOC analyst, with zero human intervention** — the bridge pushes the CIM-shaped verdict into the risk index via HEC (feeding Risk-Based Alerting) *and* back onto the originating notable via the Notable Event API, so it shows up in Incident Review and Risk Analysis automatically.

See [`ARCHITECTURE.md`](./ARCHITECTURE.md) for the full diagram, field mapping, and how each phase ties back to Takeaways 1–3.

## Contents

| File / Folder | Description |
|---|---|
| `ARCHITECTURE.md` | The three-phase agentic loop narrative behind this talk |
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

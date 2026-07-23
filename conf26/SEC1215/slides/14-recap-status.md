# Recap: Takeaways, and What's Actually Shipped

| Phase | Component | Status |
|---|---|---|
| 1 | `TA_ResponseActions` — notable → Slack JSON + `perplexity_ask` | Shipped (v1.3.0/1.3.1) |
| 2 | Slack → HEC bridge — AI verdict → CIM Risk fields | Shipped (v1.3.1) — `bin/slack_hec_bridge.py` |
| 3 | HEC → risk index, REST → notable enrichment | Shipped (v1.3.1) |

- **Takeaway 1** — full, unsummarised JSON payloads mean a smaller/cheaper LLM still has
  everything it needs; choose on cost/latency/privacy/capability, not brand.
- **Takeaway 2** — Adaptive Response + CIM + HEC + the Notable Event API are Splunk's own
  primitives; the JSON shaping, standing checks, and bridge are the glue you write once.
- **Takeaway 3** — four concrete pitfalls, all avoidable once you know they exist: notable
  API field limits, webhook's silent dead end, reply-format drift, and the scripted-input
  vs. modular-input trade-off.

## Speakers Notes

This is the direct callback slide — status table pulled verbatim from
[ARCHITECTURE.md § Status](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#status).
The three takeaway bullets are the one-line summary of slides 4, 7, and 12–13 respectively —
say each one, then point back briefly ("that's the LLM-selection slide," "that's the
build-vs-free table," "that's the four pitfalls") so the room mentally files this as a
recap, not new information.

Emphasise "Shipped" three times deliberately — every phase in this table is real, running
code as of app version **1.3.2** (a documentation/asset patch on top of the 1.3.1 feature
release), not a future-tense roadmap item. This is the credibility close before the resource
slide: "everything I've shown you today, you can clone and run tonight."

If time is tight, this is the slide to compress rather than cut — the three-takeaway
recap is what the audience should retain even if they forget every architectural detail.

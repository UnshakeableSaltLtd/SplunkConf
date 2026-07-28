# Takeaway 2: What Splunk Gives You for Free vs. What You Build

| Splunk gives you for free | You build |
|---|---|
| Adaptive Response framework | The delivery shaping (JSON payload, denylist) |
| `cim_actions.py`'s `ModularAction` — native panel reporting | The standing-question payload (`perplexity_ask` block) |
| The Perplexity Chat Completions API's `response_format` (JSON Schema) | The synchronous in-line call + the schema shape itself |
| The Notable Event API + KV store | The KV-store enrichment + custom drilldown dashboard |

**The pattern, once built, is reusable per correlation search** — you write the glue once.

## Speakers Notes

This is Takeaway 2 stated as a direct comparison table — the "repeatable pattern" the
abstract promises. Source:
[ARCHITECTURE.md § How this maps back to the session's takeaways](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#how-this-maps-back-to-the-sessions-takeaways):
"Takeaway 2 (repeatable pattern, build-vs-free)... Adaptive Response + CIM + the Notable
Event API + KV store are Splunk's own primitives; the JSON shaping, the standing checks, and
the synchronous Perplexity call are the glue you write once and reuse per correlation
search." Worth a callback here: the "you build" column used to have a fourth thing in it —
an async bridge process. It's not a column entry anymore, and that's the point: the
reusable pattern got *simpler* between v1.3.2 and v1.3.3, not more capable-looking. Slides
8–9 show what that bridge used to do and why removing it was the right trade.

Use this slide as the pivot point in the talk: slides 6–10 (Phases 1–3) are the detailed
walkthrough of exactly what sits in each column of this table. Tell the room: "keep this
table in mind — every component we show next is either something Splunk ships, or
something in this specific app that fills a gap."

Good ad-lib: `cim_actions.py`'s `ModularAction` class is what makes the notable's native
"Adaptive Responses" panel / "View Adaptive Response Invocations" audit trail work
automatically the moment you call `self.message(..., status=...)` — most people writing a
custom alert action skip this and lose that free integration point.

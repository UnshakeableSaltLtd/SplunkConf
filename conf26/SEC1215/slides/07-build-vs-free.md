# Takeaway 2: What Splunk Gives You for Free vs. What You Build

| Splunk gives you for free | You build |
|---|---|
| Adaptive Response framework | The delivery shaping (JSON payload, denylist) |
| `cim_actions.py`'s `ModularAction` — native panel reporting | The standing-question payload (`perplexity_ask` block) |
| The CIM field set / Risk data model (`All_Risk`) | The Slack → HEC bridge that maps AI text into CIM fields |
| HEC + the Notable Event API | The KV-store enrichment + custom drilldown dashboard |

**The pattern, once built, is reusable per correlation search** — you write the glue once.

## Speakers Notes

This is Takeaway 2 stated as a direct comparison table — the "repeatable pattern" the
abstract promises. Source:
[ARCHITECTURE.md § How this maps back to the session's takeaways](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#how-this-maps-back-to-the-sessions-takeaways):
"Takeaway 2 (repeatable pattern, build-vs-free)... Adaptive Response + CIM + HEC + the
Notable Event API are Splunk's own primitives; the JSON shaping, the standing checks, and
the Slack → HEC bridge are the glue you write once and reuse per correlation search."

Use this slide as the pivot point in the talk: slides 6–10 (Phases 1–3) are the detailed
walkthrough of exactly what sits in each column of this table. Tell the room: "keep this
table in mind — every component we show next is either something Splunk ships, or
something in this specific app that fills a gap."

Good ad-lib: `cim_actions.py`'s `ModularAction` class is what makes the notable's native
"Adaptive Responses" panel / "View Adaptive Response Invocations" audit trail work
automatically the moment you call `self.message(..., status=...)` — most people writing a
custom alert action skip this and lose that free integration point.

# Recap: Takeaways, and What's Actually Shipped

| Phase | Component | Status |
|---|---|---|
| 1 | `TA_ResponseActions` — notable → Slack JSON + `perplexity_ask` | Shipped (v1.3.0+) |
| 2 | Synchronous Perplexity call → `perplexity_response` | Shipped (v1.3.3) |
| 3 | Slack + notable comment + KV store write-back (same payload) | Shipped (v1.3.3, carries `perplexity_response` through paths built in v1.1.0/v1.2.0) |
| — | Slack → HEC bridge (async verdict → CIM Risk fields via HEC) | **Retired** — shipped v1.3.1–v1.3.2, removed in v1.3.3, archived at `lessons/` |

- **Takeaway 1** — full, unsummarised JSON payloads mean a smaller/cheaper LLM still has
  everything it needs; a `response_format` schema means model choice doesn't need to
  include "reliably free-texts JSON" as a criterion at all.
- **Takeaway 2** — Adaptive Response + CIM + the Notable Event API + KV store are Splunk's
  own primitives; the JSON shaping, standing checks, and synchronous Perplexity call are
  the glue you write once. Notably, that glue got *smaller* between v1.3.2 and v1.3.3.
- **Takeaway 3** — four concrete pitfalls hit building the first version: notable API
  field limits, a silent webhook dead end, reply-format drift, and a scripted-input
  configuration trade-off. Only the first is still a real constraint today — the other
  three simply don't exist anymore, because the team reacted to what they'd learned by
  trusting the Perplexity API's own structured output and Splunk's own synchronous
  execution model instead of building around them.

## Speakers Notes

This is the direct callback slide — status table pulled verbatim from
[ARCHITECTURE.md § Status](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#status).
The three takeaway bullets are the one-line summary of slides 4, 7, and 12–13 respectively —
say each one, then point back briefly ("that's the LLM-selection slide," "that's the
build-vs-free table," "that's the four pitfalls") so the room mentally files this as a
recap, not new information.

Emphasise "Shipped" three times deliberately — every phase in this table is real, running
code as of app version **1.3.3**, not a future-tense roadmap item. Then deliberately don't
skip past the fourth row: naming the retired bridge here, explicitly, as "Retired" rather
than quietly leaving it off the table, is the credibility move for this talk — it says
"we're showing you the whole arc, not just the flattering half." This is the credibility
close before the resource slide: "everything I've shown you today, including the part we
built and un-built, you can clone and run tonight."

Closing line to land before moving to slide 15: "the fastest way to end up with a simple,
correct design is often to build the more complex one first, run it for real, and pay
attention to what it costs you. We didn't get to v1.3.3 by planning it from day one — we
got there by shipping v1.3.1, trusting what it taught us, and reacting quickly."

If time is tight, this is the slide to compress rather than cut — the three-takeaway
recap is what the audience should retain even if they forget every architectural detail.

# The Agentic Loop, One Synchronous Step

```
ES Correlation Search
  └─ triggers Notable/Risk event
       └─ Adaptive Response Action: TA_ResponseActions (SHIPPED — v1.3.3)
            ├─ builds the full CIM/risk notable as JSON
            ├─ answers a "perplexity_ask" block of standing checks
            │    via a SYNCHRONOUS call to the Perplexity API, in-line,
            │    before anything is sent anywhere — JSON Schema
            │    response_format in, structured answer out, no reply to parse
            ├─ merges the answer back in as "perplexity_response"
            └─ delivers ONE payload to:
                 ├─ Slack (file_upload or webhook) — visual audit
                 ├─ the originating notable's comment trail
                 └─ the notable_slack_enrichment KV store record
```

**Detect → Decide → Act → Record** — one continuous loop, closed without a human in the
middle of it, and now closed inside a single process instead of handed off between two.

## Speakers Notes

This is the single architecture diagram the whole rest of the talk hangs off — full version
lives in
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#the-loop-at-a-glance).
Walk it top to bottom exactly once here, slowly, then tell the room "we're now going to walk
each of these three phases in detail" — this sets up slides 6–10.

Name the phases explicitly since you'll refer back to them by number for the rest of the
deck — and flag up front that Phase 2 and Phase 3 used to be two separate hops, not one:

- **Phase 1** — ES alert-action output feeds the agentic AI (shipped, `TA_ResponseActions`).
- **Phase 2** — the AI answers, in-line, before delivery (shipped, v1.3.3, inside the same
  process as Phase 1).
- **Phase 3** — that answer lands via Splunk's own existing APIs, with zero human
  intervention (shipped, v1.3.3, same call as Phase 2 — no second component).

Tell the room honestly, right here, that this diagram is the *second* version of this
architecture, not the first: the first shipped design (v1.3.1–v1.3.2) split Phase 2/3 out
into a separate asynchronous bridge component that polled Slack for a reply. It worked. It's
still worth seeing — slides 8–9 walk through it, because building it and retiring it is where
Takeaway 3 actually comes from. What's on screen now is what replaced it, once the cost of
running a second component became obvious and the fix turned out to be simpler than the
original design: trust the Perplexity API's own structured-output feature and trust that the
alert action already had everything it needed synchronously, with no hand-off required.

Emphasise the closing line — this is the "retaining the principles of being agentic" test
this whole pipeline has to pass: detect (correlation search) → decide (agentic AI against
the standing `perplexity_ask` checks) → act (Slack + notable comment + KV store write-back)
→ record (native Adaptive Response panel, Incident Review) — one continuous loop, closed
without a human in the middle of it, and now closed synchronously in one request/response
rather than an async poll. This exact phrase and diagram are from
[ARCHITECTURE.md § The loop at a glance](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#the-loop-at-a-glance).

Everything here is already shipped — this is not a roadmap slide. Status detail, including
the retired first version, comes back on slide 14.

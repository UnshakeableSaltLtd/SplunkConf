# The Three-Phase Agentic Loop

```
ES Correlation Search
  └─ triggers Notable/Risk event
       └─ Adaptive Response Action: TA_ResponseActions (SHIPPED — v1.3.0/1.3.1)
            └─ full CIM/risk notable as JSON → Slack (file_upload or webhook)
                 + a "perplexity_ask" block of standing checks + strict
                   JSON reply_format
                      └─ Agentic AI (Perplexity) reads the JSON, answers the
                         standing checks, returns a verdict
                           └─ Slack → HEC Bridge (SHIPPED — v1.3.1,
                              bin/slack_hec_bridge.py)
                                └─ maps the AI's verdict into CIM-compliant
                                   fields and re-injects via Splunk's own
                                   APIs — HEC for the risk index, REST for
                                   the notable
```

**Detect → Decide → Act → Record** — one continuous loop, closed without a human in the
middle of it.

## Speakers Notes

This is the single architecture diagram the whole rest of the talk hangs off — full version
lives in
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#the-loop-at-a-glance).
Walk it top to bottom exactly once here, slowly, then tell the room "we're now going to walk
each of these three phases in detail" — this sets up slides 6–10.

Name the three phases explicitly since you'll refer back to them by number for the rest of
the deck:

- **Phase 1** — ES alert-action output feeds the agentic AI (shipped, `TA_ResponseActions`).
- **Phase 2** — the AI's answer becomes a CIM-compliant event (shipped, v1.3.1,
  `bin/slack_hec_bridge.py`).
- **Phase 3** — Splunk's own APIs place it for the SOC analyst, with zero human intervention
  (shipped, v1.3.1).

Emphasise the closing line — this is the "retaining the principles of being agentic" test
this whole pipeline has to pass: detect (correlation search) → decide (agentic AI against
the standing `perplexity_ask` checks) → act (HEC risk write + notable enrichment) → record
(native Adaptive Response panel, Incident Review, Risk Analysis) — one continuous loop,
closed without a human in the middle of it. This exact phrase and diagram are from
[ARCHITECTURE.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md).

Everything here is already shipped — this is not a roadmap slide. Status detail comes back
on slide 14.

# Phase 3: Splunk's Own APIs Close the Loop — Zero Human Touch

Two existing Splunk APIs, not a bespoke store:

- **HTTP Event Collector → the risk index.** The bridge POSTs the CIM-shaped event to HEC
  (`index=risk` by default) — the same mechanism `sendalert risk` uses internally. It's
  immediately picked up by the `All_Risk` data model and folds into that object's existing
  risk score, feeding Risk-Based Alerting exactly like a native correlation search's risk
  modifier would.
- **The Notable Event API → the originating notable.** The bridge writes the verdict back
  to the *same* notable via its `event_id`, extending the comment write-back and KV-store
  enrichment `TA_ResponseActions` already does — visible directly in Incident Review.

No analyst forwards, tags, or re-keys anything. The moment the AI replies in Slack, both
writes happen automatically.

## Speakers Notes

This is Phase 3 — the payoff of Phases 1 and 2. Source:
[ARCHITECTURE.md § Phase 3](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#phase-3--leveraging-splunks-own-apis-so-it-lands-with-zero-human-touch-shipped-v131).

Emphasise "not a bespoke store" — this is the point where the "build vs. free" framing
(slide 7) pays off most visibly: the bridge doesn't invent a new place for the AI's
opinion to live, it uses the *exact same two integration points* a native ES component
would use. Reference for the Notable Event API's actual capabilities/limits:
[Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference).

Close this slide with the full "retaining the principles of being agentic" loop, repeated
from slide 5 but now every step has been shown concretely: **detect** (correlation search)
→ **decide** (agentic AI against the standing `perplexity_ask` checks) → **act** (HEC risk
write + notable enrichment) → **record** (native Adaptive Response panel, Incident Review,
Risk Analysis) — one continuous loop, closed without a human in the middle of it.

Transition line into the demo: "so let's actually see this fire, end to end."

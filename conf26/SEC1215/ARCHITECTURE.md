# SEC1215 Talk Narrative: The Three-Phase Agentic Loop

This is the architecture arc for the session — how a Splunk Enterprise Security
notable becomes an agentic AI decision, and how that decision gets back into
Splunk in a form the platform actually understands, with no analyst copy/paste
in the loop. It builds directly on [`TA_ResponseActions`](../TA_ResponseActions/README.md)
and is the "what to build yourself vs. what Splunk gives you for free" spine
referenced in Takeaway 2.

## The loop at a glance

```
ES Correlation Search
   └─ triggers Notable/Risk event
        └─ Adaptive Response Action: TA_ResponseActions (SHIPPED — v1.3.0/1.3.1)
             └─ full CIM/risk notable as JSON -> Slack (file_upload or webhook)
                  + a "perplexity_ask" block of standing checks + strict
                  JSON reply_format (repo check / user check / source IP
                  check, reply as {risk_score, risk_object, ...})
                       └─ Agentic AI (Perplexity) reads the JSON, answers the
                          standing checks, returns a verdict
                            └─ Slack -> HEC Bridge (SHIPPED — v1.3.1,
                               bin/slack_hec_bridge.py)
                                 └─ maps the AI's verdict into CIM-compliant
                                    fields and re-injects via Splunk's own
                                    APIs — HEC for the risk index, REST for
                                    the notable — so it lands in both places
                                    an analyst already looks, automatically.
```

## Phase 1 — ES alert-action output feeds the agentic AI (shipped)

`TA_ResponseActions` (Adaptive Response Action `notable_to_slack_json`) is the
piece that already exists: it takes the triggering notable/finding, keeps
every CIM/risk/notable field, strips noise fields, and delivers it to Slack as
a complete JSON payload — no size-limited summary, no lossy formatting. As of
v1.3.0 it also ships a `perplexity_ask` block in `param.additional_fields`
by default: three standing checks (is `$result.repo$` a repo we commonly see
for this finding type, is `$result.user$` expected/authorised, is `$result.src$`
low-threat) that travel with every notable so the agentic AI always has a
consistent, structured question to answer — not just a raw event dump.

This is the "what Splunk gives you for free vs. what you build" line in
practice: Splunk gives you the Adaptive Response framework, `cim_actions.py`'s
`ModularAction` for native panel reporting, and the CIM field set for free —
the delivery shaping and the standing-question payload are what you build.

## Phase 2 — the AI's answer becomes a CIM-compliant event (shipped, v1.3.1)

The gap the talk calls out: an LLM's reply is prose, or at best loose JSON.
Splunk's Risk Analysis framework and Incident Review don't care what an LLM
*said* — they care about fields. A risk modifier in the risk index is only
usable by the Risk Analysis and Incident Review dashboards once it carries,
at minimum, `risk_object`, `risk_object_type`, and `risk_score`, because the
Risk data model (`All_Risk`) accelerates exactly those fields and the overall
risk score for an object is the sum of every risk modifier's `risk_score`
for it ([Risk Analysis framework](https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework)).
`risk_message` exists specifically so a search (or, here, an automation) can
customise the human-readable reason for the score
([CIM Risk data model reference](https://dev.splunk.com/view/enterprise-security/SP-CAAAFBM)).

So the **Slack → HEC bridge** (`bin/slack_hec_bridge.py`, shipped in v1.3.1) is
the component that turns the agentic AI's free-text verdict into that shape
before anything is written back. Concretely, it's a classic Splunk scripted
input (`default/inputs.conf`) that polls the `notable_slack_enrichment` KV
store every 60 seconds for records `TA_ResponseActions` has flagged
`awaiting_ai_response=1`, reads the Slack thread with `conversations.replies`,
and parses the reply against the strict JSON schema now pinned into
`alert_actions.conf`'s `perplexity_ask.reply_format`:

| AI verdict concept | CIM Risk field it becomes |
|---|---|
| "Which user/host/IP is this about" | `risk_object` + `risk_object_type` |
| "How risky is this, on our scale" | `risk_score` |
| "Why — the AI's reasoning, in one line" | `risk_message` |
| Which correlation search / notable this ties back to | `orig_sid` / `orig_rid` / `event_id` (carried through from the same `sid`/`rid` `TA_ResponseActions` already uses for its KV-store enrichment) |

This is the piece that makes the AI's output *CIM compliant*, not just valid
JSON — it's the difference between "the AI said something" and "Splunk can
correlate, score, and dashboard what the AI said" alongside everything else
already flowing through Enterprise Security.

## Phase 3 — leveraging Splunk's own APIs so it lands with zero human touch (shipped, v1.3.1)

Once the verdict is CIM-shaped, the bridge uses two existing Splunk APIs —
not a bespoke store — to put it exactly where a SOC analyst already looks,
with no one relaying Slack messages back into Splunk by hand:

- **HTTP Event Collector → the risk index.** The bridge POSTs the CIM-shaped
  event to HEC as a risk modifier (the same mechanism the `sendalert risk`
  search command uses internally). Because it lands in the risk index with
  `risk_object`/`risk_object_type`/`risk_score` populated, it's picked up by
  the `All_Risk` data model and folds straight into that object's existing
  risk score and the Risk Analysis dashboard — the AI's finding contributes
  to Risk-Based Alerting the same way a native correlation search's risk
  modifier would.
- **The Notable Event API → the originating notable.** In parallel, the
  bridge extends what `TA_ResponseActions` already does (the `notable_update`
  comment write-back and the `notable_slack_enrichment` KV-store record
  described in [its README](../TA_ResponseActions/README.md#closing-the-loop-getting-the-result-back-to-the-analyst))
  so the AI's structured verdict — not just a comment string — is attached to
  the *same* notable via its `event_id`
  ([Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference)),
  so it's visible directly in Incident Review, not just discoverable via a
  separate drilldown dashboard.

Both writes happen from the bridge automatically the moment the AI responds
in Slack — no analyst forwards, tags, or re-keys anything. That's the
"retaining the principles of being agentic" test for this whole pipeline:
detect (correlation search) → decide (agentic AI against the standing
`perplexity_ask` checks) → act (HEC risk write + notable enrichment) →
record (native Adaptive Response panel, Incident Review, Risk Analysis) — one
continuous loop, closed without a human in the middle of it.

## How this maps back to the session's takeaways

- **Takeaway 1** (choosing the right LLM) is why Phase 1's payload is a full,
  denylist-scrubbed JSON export rather than a squeezed summary — a smaller/
  cheaper model still gets the complete picture to reason over.
- **Takeaway 2** (repeatable pattern, build-vs-free) is this whole document:
  Adaptive Response + CIM + HEC + the Notable Event API are Splunk's own
  primitives; the JSON shaping, the standing checks, and the Slack → HEC
  bridge are the glue you write once and reuse per correlation search.
- **Takeaway 3** (avoiding pitfalls) includes the Phase 2 lesson directly:
  the first version of this pipeline treated the AI's Slack reply as "done"
  once posted — it took a second pass to realise *posted to Slack* isn't
  *usable by Splunk* until it's reshaped into CIM fields and pushed back
  through HEC/REST, not left for an analyst to translate by hand. Building
  the v1.3.1 bridge surfaced several more pitfalls worth calling out
  explicitly for anyone repeating this pattern:

  1. **The Notable Event API can't carry new structured fields.**
     `/services/notable_update` only accepts `comment`/`status`/`urgency`/
     `newOwner`/`disposition`
     ([API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference)) —
     there is no REST call that attaches a new indexed field to an existing
     notable after the fact. "Notable enrichment" in Phase 3 therefore has to
     reuse the KV-store + custom-drilldown pattern `TA_ResponseActions`
     already built in v1.2.0 (structured fields, rendered via a dashboard)
     and fall back to a plain-text comment for anything visible directly in
     Incident Review — it is not a new REST write capability, however much
     the talk's narrative might make it sound like one.
  2. **Webhook delivery silently can't be bridged.** Slack's Incoming
     Webhooks carry no bot token and no `conversations.read` scope, so
     there is no API call that reads a reply back out of a webhook-posted
     message. A correlation search wired to `delivery_method=webhook`
     still delivers to Slack fine — it just never gets a Phase 2/3 verdict,
     and nothing errors to tell you that. This only surfaces if you notice
     `awaiting_ai_response` never got set to `1` on that record.
  3. **LLM reply-format drift.** Free-text answers to the original
     `perplexity_ask` checks were unparseable — the fix was to make the
     required JSON shape part of the *prompt itself*
     (`perplexity_ask.reply_format` in `alert_actions.conf`), and to have
     `slack_hec_bridge.py` log-and-skip (not crash) on any reply that still
     doesn't parse, leaving the KV record `awaiting_ai_response=1` so the
     raw reply stays visible for a human to check rather than being lost.
  4. **Modular input scheme overhead wasn't worth it for an internal
     poller.** `slack_hec_bridge.py` is registered as a plain classic
     scripted input (`[script://...]` in `inputs.conf`), not a full
     `splunklib.modularinput` scheme. The trade-off: Splunk Web doesn't
     auto-generate a settings page for its custom keys (`risk_index`,
     `hec_url`, the credential realms) — they're self-parsed out of
     `inputs.conf` via `configparser` instead, and must be edited by hand
     in `local/inputs.conf`. Fine for a single internal component; would be
     the wrong call for anything meant to be configured by someone other
     than the app's own maintainer.

## Status

| Phase | Component | Status |
|---|---|---|
| 1 | `TA_ResponseActions` — notable → Slack JSON + `perplexity_ask` | Shipped (v1.3.0/1.3.1) |
| 2 | Slack → HEC bridge — AI verdict → CIM Risk fields | Shipped (v1.3.1) — `bin/slack_hec_bridge.py` |
| 3 | HEC → risk index, REST → notable enrichment | Shipped (v1.3.1) — reuses the `sid`/`rid`/`event_id` correlation keys already established by `TA_ResponseActions` v1.2.0's KV-store enrichment |

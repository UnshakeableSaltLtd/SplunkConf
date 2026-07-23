# Takeaway 3: Pitfalls We Hit — Part 1

**Pitfall 1 — The Notable Event API can't carry new structured fields.**
`/services/notable_update` only accepts `comment` / `status` / `urgency` / `newOwner` /
`disposition`. There is no REST call that attaches a new indexed field to an existing
notable after the fact — "notable enrichment" has to fall back to a KV-store +
custom-drilldown pattern, plus a plain-text comment for anything visible directly in
Incident Review.

**Pitfall 2 — Webhook delivery silently can't be bridged.**
Slack Incoming Webhooks carry no bot token and no `conversations.read` scope — there's no
API call that reads a reply back out of a webhook-posted message. A correlation search
wired to `delivery_method=webhook` still delivers fine — it just never gets a Phase 2/3
verdict, and **nothing errors to tell you**.

## Speakers Notes

Source for both pitfalls, verbatim from the architecture doc:
[ARCHITECTURE.md § Takeaway 3 pitfalls](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#how-this-maps-back-to-the-sessions-takeaways).

**Pitfall 1 detail:** cite the actual API reference so the audience can verify this
themselves —
[Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference).
The lesson: don't assume "notable enrichment" means a new indexed field appears on the
notable itself — in practice it means "a comment, plus a structured record surfaced via a
custom drilldown," which is exactly what `TA_ResponseActions` v1.2.0 already built before
Phase 2/3 existed. This is worth saying plainly to the room: the talk's narrative can make
this sound like a new REST write capability; it isn't one.

**Pitfall 2 detail:** this is the "silent failure" pitfall — the most dangerous kind,
because there's no exception, no log error, nothing. The only symptom is that
`awaiting_ai_response` never flips to `1` on that KV-store record, so the bridge never picks
it up. Practical advice for the room: if you're demoing or troubleshooting this pattern and
Phase 2/3 "just isn't happening" for a given notable, check `delivery_method` on that
correlation search's action config *first*, before debugging the bridge itself. Also
referenced in
[TA_ResponseActions README § Known limitation](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#phase-23-closing-the-agentic-loop-binslack_hec_bridgepy).

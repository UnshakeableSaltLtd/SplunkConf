# Takeaway 3: Pitfalls We Hit — Part 1

**Pitfall 1 — The Notable Event API can't carry new structured fields.**
`/services/notable_update` only accepts `comment` / `status` / `urgency` / `newOwner` /
`disposition`. There is no REST call that attaches a new indexed field to an existing
notable after the fact — "notable enrichment" has to fall back to a KV-store +
custom-drilldown pattern, plus a plain-text comment for anything visible directly in
Incident Review.

**Pitfall 2 — Solved by deletion: webhook delivery used to silently break the loop.**
The first design (v1.3.1–v1.3.2) had to read a reply back out of Slack, and Incoming
Webhooks carry no bot token to do that with — a correlation search wired to
`delivery_method=webhook` still delivered fine, it just never got a verdict, and **nothing
errored to tell you**. v1.3.3 doesn't read anything back out of Slack at all, so this
entire failure class is gone — not fixed, *removed*, by trusting the alert action's own
synchronous context instead of a second read path.

## Speakers Notes

Source for both pitfalls, verbatim from the architecture doc:
[ARCHITECTURE.md § Lesson: the Slack to HEC bridge, retired](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#lesson-the-slack-to-hec-bridge-retired).

**Pitfall 1 detail:** cite the actual API reference so the audience can verify this
themselves —
[Notable Event API reference](https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.3/notable-event-endpoints/notable-event-api-reference).
The lesson: don't assume "notable enrichment" means a new indexed field appears on the
notable itself — in practice it means "a comment, plus a structured record surfaced via a
custom drilldown," which is exactly what `TA_ResponseActions` v1.2.0 already built before
Phase 2/3 existed. This is worth saying plainly to the room: the talk's narrative can make
this sound like a new REST write capability; it isn't one.

**Pitfall 2 detail:** frame this one differently from Pitfall 1 — it's not "here's a
constraint you still have to live with," it's "here's a whole category of bug the team
doesn't have anymore, and here's exactly why." This was the "silent failure" pitfall — the
most dangerous kind, because there was no exception, no log error, nothing; the only
symptom was that `awaiting_ai_response` never flipped to `1` on that KV-store record, so
the bridge never picked it up. The reaction, once this was understood: don't add a check
for it, don't add a warning log for it, remove the thing that made it possible — the
synchronous call in v1.3.3 has no delivery-method dependency because it never reads
anything back out of Slack at all. That's the "trusted the platform" move in concrete
form: trusting that the alert action already had every byte it needed, in-process, meant
not needing a second read path in the first place. Source for what replaced it:
[TA_ResponseActions README § Perplexity API: synchronous ask/response](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#perplexity-api-synchronous-askresponse).

# Lessons: two designs that didn't ship

This folder holds retired artifacts kept purely as "before" reference material
for the SEC1215 talk — neither is installed or referenced by the shipping
`TA_ResponseActions` app. Both are real designs that were actually built and
tested, then deliberately abandoned in favor of a simpler approach. That
trade-off *is* the lesson (see Takeaway 3: avoid the pitfalls that cost time
before delivering value).

## 1. The hourly-cron ES Findings → HEC recreate-prompt

`recreate-es-findings-hec-task-prompt.md` is the exact prompt used to stand up
an hourly scheduled search that pulled Enterprise Security Findings and
forwarded them to a Splunk HTTP Event Collector endpoint. It's kept here as a
concrete, reusable example of "recreate this task from scratch" prompting —
useful for the talk's discussion of what to script/automate yourself vs. what
Splunk gives you for free — but the cron itself was never revived; the
adaptive-response-action approach in `TA_ResponseActions` replaced it.

## 2. The Slack → HEC bridge (Phase 2/3 of the original three-phase loop)

`slack_hec_bridge.py.retired` (+ its `inputs.conf`/`inputs.conf.spec`
registration, `bridge_inputs.conf.retired` / `bridge_inputs.conf.spec.retired`)
was a scripted input that closed the agentic loop asynchronously:

1. `notable_to_slack_json.py` posts the notable + a `perplexity_ask` block to
   Slack and marks the KV store record `awaiting_ai_response=1`.
2. The bridge polls that flag every 60 seconds, reads the agentic AI's reply
   back out of the Slack thread via `conversations.replies`, parses it against
   a fixed `reply_format` JSON shape, and maps the verdict onto CIM Risk data
   model fields (`risk_object`, `risk_object_type`, `risk_score`,
   `risk_message`).
3. It pushes that CIM-shaped event to Splunk's risk index via HEC (feeding
   Risk-Based Alerting) and writes an enrichment comment back onto the
   originating notable — with no human intervention.

It shipped in `TA_ResponseActions` 1.3.1–1.3.2. It worked, but it added real
operational overhead for what it delivered:

- **A second moving part with its own failure modes** — a polling interval,
  thread-ts plumbing tying the bridge to Slack's specific reply-threading
  behavior, and a `reply_format` contract that had to be perfectly followed by
  a chat reply or parsing silently failed.
- **A classic scripted input, not a real modular input** — `inputs.conf`
  couldn't deliver its custom keys (`risk_index`, `hec_url`,
  `hec_token_realm`, `slack_bot_token_realm`) through Splunk's normal modular
  input protocol, so the script had to self-parse its own stanza via
  `configparser`. That meant no auto-generated Splunk Web config page, and one
  more undocumented trap for the next admin.
- **A whole extra credential realm and HEC token** (`hec_risk_bridge`) just to
  write back data the alert action already had in hand at send time.
- **Latency and a race window** — the loop only closed once Slack, a human (or
  nothing) triggered a reply, and the next poll interval ticked over. The
  "zero human intervention" framing only held if nobody read the thread first.

None of that was necessary. The alert action *already has* the full notable
context when it runs — there's no reason to round-trip it through Slack and
poll for an answer. **v1.3.3 replaces the bridge with a synchronous Perplexity
API call made directly inside `notable_to_slack_json.py`**: the same
`perplexity_ask` block is answered in-line, right before delivery, and the
result (`perplexity_response`) is merged into the same payload that goes to
Slack (for visual audit, unchanged) and the same write-back paths (notable
comment + KV store) that already existed. One process, one credential, one
request/response — no polling, no thread-ts, no second index. See
[`../ARCHITECTURE.md`](../ARCHITECTURE.md) and
[`../../TA_ResponseActions/README.md`](../../TA_ResponseActions/README.md) for
the current, shipping design.

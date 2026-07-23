# Phase 1: ES Alert Action Feeds the Agentic AI

`TA_ResponseActions` — a custom Adaptive Response Action, `notable_to_slack_json`:

- Takes the triggering notable/finding and delivers it to Slack as a **complete JSON
  payload** — every CIM/risk/notable field, noise fields stripped, no size-limited summary.
- Ships a standing **`perplexity_ask`** block by default in `param.additional_fields`:
  three checks that travel with every notable —
  - Is `$result.repo$` a repo we commonly see for this finding type?
  - Is `$result.user$` an expected/authorised user?
  - Is `$result.src$` a low-threat source IP?
- Two delivery modes: **file_upload** (bot token, no size limit) or **webhook** (quick
  setup, truncates large payloads).

## Speakers Notes

This is Phase 1 of the loop, detailed. Source:
[ARCHITECTURE.md § Phase 1](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md#phase-1--es-alert-action-output-feeds-the-agentic-ai-shipped)
and the app's own
[README.md](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md).

Key point to land: this isn't a lossy summary sent to the LLM — it's the *entire* CIM/risk
event, denylist-scrubbed only for noise fields (`_raw`, `_time`, `_indextime`, `_cd`, `_bkt`,
`_si`, `splunk_server`, `timestartpos`, `timeendpos`, `eventtype`, `punct`), so the agentic
AI is reasoning over the same data an analyst would see, not a paraphrase of it.

On delivery modes: file_upload uses Slack's `files.getUploadURLExternal` /
`files.completeUploadExternal` flow specifically because Slack retired the older
`files.upload` endpoint on 2025-11-12 — reference:
[Slack feature and plan retirements](https://slack.com/help/articles/4426294050451-Slack-feature-and-plan-retirements).
Flag here (without dwelling — it comes back as a pitfall on slide 12) that webhook delivery
is the quick-start path but can't be bridged back into Splunk at all in Phase 2/3, because
Incoming Webhooks carry no bot token.

The `perplexity_ask` block is the "standing question" pattern worth calling out: every
notable gets the *same* structured question, so the agentic AI's job is narrow and
repeatable (three checks, one JSON reply) rather than open-ended free-form analysis — this
is what keeps a smaller/cheaper model (Takeaway 1, slide 4) viable.

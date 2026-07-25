# Recreate: "Hourly ES Findings triage -> Splunk HEC" Scheduled Task

This file is a self-contained prompt. Paste the **Recreation Prompt** section below into
Perplexity Computer (or adapt it for any other AI agent that supports scheduled/recurring
tasks, tool calls, and a persistent file/key-value store) to stand the automation back up
from scratch, with the same behaviour it had in production.

## What this task does

A background agent runs on an hourly cadence, reads new notable messages posted by
`TA_ResponseActions` (Phase 1) into the Slack channel `#es-findings`, answers the standing
`perplexity_ask` questions attached to each notable, and writes the result back to Splunk
via HTTP Event Collector — with Slack emoji reactions used as a lightweight status
indicator (in progress / done / failed) on each source message. It is functionally a
second, AI-agent-hosted implementation of the same "close the loop" idea documented for the
Slack → HEC bridge in
[TA_ResponseActions/README.md § Closing the loop](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/TA_ResponseActions/README.md#closing-the-loop-getting-the-result-back-to-the-analyst),
except the "bridge" here is a scheduled AI agent task rather than a Splunk-side Python
scripted input.

## Prerequisites before recreating

Any agent recreating this needs, at minimum:

1. **Read access to Slack channel history** for the target channel (here, `#es-findings`,
   channel ID `C0BKA6D4AFL`) — a proper Slack app/connector scope
   (`channels:history`/`groups:history`/`im:history`/`mpim:history`), not just a bare bot
   token, since plain OAuth bot tokens without those scopes will fail with
   `missing_scope` on `conversations.history`.
2. **A Slack bot token** scoped for `reactions:read`, `reactions:write`, `files:read`,
   `files:write`, `chat:write`, `chat:write.public`, `channels:join` — used for
   `reactions.add`/`reactions.remove`, `files.info`, and (if ever needed) posting messages.
   In this deployment that token is stored as a named credential scoped to
   `slack.com` and invoked from shell commands, kept separate from the channel-history read
   path (which goes through a first-class Slack connector/tool instead of a raw API call).
3. **Network + credentials for the target Splunk HTTP Event Collector** —
   `https://splunk.unshakeablesalt.net:8088/services/collector/event`, an HEC token, and (in
   this environment) TLS verification disabled because the endpoint uses a self-signed
   certificate.
4. **GitHub CLI/API access** (read-only is enough) for any `perplexity_ask` question that
   requires checking whether a repo is one commonly associated with a given finding type.
5. **General web search / a public IP geolocation-reputation API** (e.g. ip-api.com) for any
   `perplexity_ask` question about source IPs.
6. **A persistent store for one piece of state across runs**: the Slack message timestamp
   (`ts`) of the last fully-processed message, so each run only looks at messages newer than
   the previous run. A single text file works fine; a key-value store works too.
7. **A way to schedule a recurring background job on (approximately) an hourly cadence**,
   with no exact-minute requirement — jittering the run a few minutes off the hour is fine
   and, in fact, preferred to avoid thundering-herd effects across many scheduled jobs.

## Recreation Prompt

Copy everything in the fenced block below and give it to the agent, alongside instructing
it to schedule this as a recurring hourly background task (`cron="0 * * * *"`,
`background=true`, `exact=false` if using Perplexity Computer's `schedule_cron` tool).

``` MCP
You are the recurring hourly bridge between the Slack channel #es-findings (channel_id C0BKA6D4AFL) and a Splunk HTTP Event Collector, with Slack reaction status indicators.

1. Maintain a tracking file at /home/user/workspace/cron_tracking/es_findings_hec/last_ts.txt containing the Slack message timestamp (ts) of the last message you fully processed. If the file doesn't exist yet, create the directory, read the current latest message ts in the channel, save it to the file, and skip processing on this very first run (nothing to backfill) -- just initialize and end.
2. On every run after that: read #es-findings (channel_id C0BKA6D4AFL) for messages with ts greater than the value in the tracking file, oldest first. IMPORTANT: do this via the Slack connector tool (call_external_tool with source_id 'slack_direct', tool_name 'slack_read_channel' or equivalent channel-history tool) -- do NOT use bash/curl with api_credentials=['custom-cred:slack.com'] for reading messages/history. That custom credential is scoped ONLY for reactions.add/remove, files.info, and chat.postMessage (reactions:read, reactions:write, files:write, files:read, chat:write, chat:write.public, channels:join) and lacks channels:history/groups:history/mpim:history/im:history, so any raw Slack Web API call to conversations.history (or similar) via that credential will fail with missing_scope. Keep using api_credentials=['custom-cred:slack.com'] for the reaction and files.info calls later in this task (steps 4b and 6/9) -- only channel-history reading must go through the connector tool instead.
3. If there are no new messages, end the run silently -- do not call send_notification, do not call the Splunk endpoint, do not add any reactions.
4. For each message, obtain the raw notable JSON payload text -- it can arrive in one of two shapes depending on how the Splunk alert action delivered it:
   a. TEXT/WEBHOOK SHAPE: the message body contains a fenced code block (```...```) or a bare JSON object. Use that text (with the ``` fences stripped) as the payload text.
   b. FILE-ATTACHED SHAPE: the message body has NO JSON in it -- instead it just has two lines like "Notable - <name>" / "Event time: <time>" plus a line such as "Files: <filename> (ID: <FILE_ID>, ...)". Extract <FILE_ID> from that line with a regex (e.g. `ID:\s*([A-Z0-9]+)`), then fetch its content with:
      bash curl -s -m 15 "https://slack.com/api/files.info?file=<FILE_ID>" with api_credentials=['custom-cred:slack.com']
      If the response has "ok": true, use its top-level "content" field (itself a JSON string) as the payload text. If "ok" is false, or "is_truncated" is true and the content field doesn't parse as valid JSON, treat this message as invalid.
   c. Parse the resulting payload text as JSON. The current alert action's envelope nests most notable-specific fields under a "notable" object and keeps search_name/sid/app/owner/results_link/server_host at the top level -- so when reading any field (repo, user, src, src_ip, event_id, rule_id, etc.), check BOTH the top level AND payload["notable"] for it, preferring the top level if both are present. A "perplexity_ask" object may be at the top level OR inside payload["additional_fields"] (or, for older/other producers, inside payload["notable"]) -- check all three locations for it.
   d. If the payload text doesn't parse as valid JSON by either path above, or no "perplexity_ask" object is found in any of those locations, skip the message entirely (no reaction, still advance the tracking file past it).
5. Determine notable_id, checking each of these in order at the top level first, then inside "notable": source_guid, detection_id, source_event_id, sid, event_id, rule_id. Use "unknown" if none are present.
6. As soon as you start processing a valid finding message (before doing the research), add a :large_green_circle: reaction to it to show it's being worked on: bash curl -s -m 15 https://slack.com/api/reactions.add -H 'Content-Type: application/json; charset=utf-8' -d '{"channel": "C0BKA6D4AFL", "timestamp": "<message ts>", "name": "large_green_circle"}' with api_credentials=['custom-cred:slack.com']. If this call returns ok:false with error 'already_reacted', ignore and continue. Never put the raw Slack token in any command, file, or log -- it is injected automatically via api_credentials, do not add your own Authorization header.
7. For every key in the "perplexity_ask" object you found, actually answer/address that specific question using whatever tools and context are relevant (web search, GitHub lookups via bash with api_credentials=['github'] using gh/git CLIs, IP geolocation/reputation lookups via curl to a public geoip API like ip-api.com, etc.). Resolve any $result.<field>$-style tokens left unsubstituted in the ask text using the fields you found in step 4c. Build a 'perplexity_response' JSON object with the SAME keys as perplexity_ask, each mapped to a concise answer (1-3 sentences). Add one extra key 'overall' with a short overall risk read-out synthesizing all the sub-answers (e.g. any indicators of compromise, anything atypical worth flagging).
8. POST a JSON event to the Splunk HEC using bash with api_credentials=['custom-cred:splunk.unshakeablesalt.net'] (use curl with -k since the cert may be self-signed):
   curl -s -m 15 -H 'Content-Type: application/json' https://splunk.unshakeablesalt.net:8088/services/collector/event -k -d '<json body>'
   JSON body shape:
   {"event": {"notable_id": "<notable_id>", "search_name": "<search_name if present, else omit>", "perplexity_ask": <the original perplexity_ask object>, "perplexity_response": <your perplexity_response object built in step 7>, "processed_at": "<current UTC ISO8601 timestamp>", "slack_permalink": "https://unshakeablesalt.slack.com/archives/C0BKA6D4AFL/p<message ts with the decimal point removed>"}, "index": "perplexity", "sourcetype": "_json"}
9. Check the HEC HTTP response.
   - If it IS a 200 with {"code":0,"text":"Success"}: remove the :large_green_circle: reaction (reactions.remove, same auth) and add a :100: reaction (reactions.add) to the same message, both via api_credentials=['custom-cred:slack.com'].
   - If it is NOT a 200/success response: remove the :large_green_circle: reaction and add a :rotating_light: reaction instead (same auth), and call send_notification with title 'Splunk HEC write-back failed', body including the notable_id and the error response. This is the only case where you should call send_notification.
   - If the reactions.remove call fails because the reaction was already removed, ignore and continue -- don't treat that as a task failure.
10. After successfully processing (or intentionally skipping) all new messages, update /home/user/workspace/cron_tracking/es_findings_hec/last_ts.txt to the ts of the newest message you looked at, so the next run starts from there.
11. Do not send any routine 'all good' notification -- stay silent on successful runs with no failures beyond the reaction updates themselves.
```

## Scheduling parameters (Perplexity Computer)

If recreating via Perplexity Computer's own scheduling tool, use:

- **name:** `Hourly ES Findings triage -> Splunk HEC`
- **cron:** `0 * * * *` (once per hour, on the hour — the platform will jitter the actual
  run minute for load distribution unless `exact` is set)
- **background:** `true` (self-contained; no prior conversation context needed)
- **exact:** `false` (hourly cadence, precise minute doesn't matter)

## Adapting for a different AI agent / platform

The task text above uses Perplexity Computer–specific mechanics (`call_external_tool` with
`source_id: slack_direct`, `api_credentials=['custom-cred:...']`, `send_notification`). To
port this to another agent framework, replace each with its equivalent:

| Perplexity Computer mechanism | Generic equivalent needed |
| --- | --- |
| `call_external_tool(source_id='slack_direct', tool_name='slack_read_channel')` | Any Slack Web API client with `conversations.history` + channel-history OAuth scopes |
| `api_credentials=['custom-cred:slack.com']` (shell curl) | A stored Slack bot token, injected into requests to `reactions.add`/`reactions.remove`/`files.info` |
| `api_credentials=['custom-cred:splunk.unshakeablesalt.net']` | A stored Splunk HEC token, injected into the `Authorization: Splunk <token>` header for the POST in step 8 |
| `api_credentials=['github']` | Any authenticated `gh`/GitHub REST client for read-only repo lookups |
| `send_notification` | Whatever alerting channel the host platform/agent uses (email, Slack DM, webhook, etc.) |
| The scheduling wrapper itself (`schedule_cron`) | Any cron-style scheduler, serverless scheduled function, or workflow-orchestration trigger capable of firing hourly and persisting the tracking file/state between runs |

## Historical note on first-run seeding (not needed for a fresh recreation)

When this task was originally deployed, the tracking-file bootstrap in step 1 was
temporarily overridden with a one-time seed value so that two specific pre-existing test
notables (Slack message timestamps `1784828999.033719` and `1784829007.467649`, posted
2026-07-23) would be treated as backlog and processed on the very first run, instead of
being skipped as pre-existing baseline. That override is **not part of the reusable prompt
above** and is not needed when recreating this task from scratch — a clean recreation should
just let step 1 initialize normally to the current latest message ts on its first run.

## Status

This scheduled task was paused (deleted) on 2026-07-23 to save credits while the SEC1215
presentation work is in progress. This file exists so it can be recreated exactly as it was
once needed again — either by pasting the Recreation Prompt into Perplexity Computer, or by
using the same instructions as a spec for any other AI agent framework.

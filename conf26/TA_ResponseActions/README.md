# TA_ResponseActions

**App Name:** Notable to Perplexity
**Version:** 1.3.4
**Author:** David Pollard, Unshakeable Salt Ltd
**Associated Session:** [SEC1215 — From Zero to Agentic](../SEC1215/README.md)

## Overview

Custom Splunk Enterprise Security **Adaptive Response Action** that sends the triggering
Notable/Finding to Perplexity and Slack as a complete JSON payload — every CIM/risk/notable field, plus
any user-defined additional fields merged in at send time.

Two delivery modes:

- **file_upload** (recommended) — uses a Slack bot token via `files.getUploadURLExternal` /
  `files.completeUploadExternal` to deliver the entire JSON with no size limit ([Slack retired
  `files.upload` on 2025-11-12](https://slack.com/help/articles/4426294050451-Slack-feature-and-plan-retirements)).
- **webhook** — quick to set up via an Incoming Webhook, but truncates large payloads to fit
  Slack's block limits.

## Requirements

- Splunk Enterprise Security 7.x+ on Splunk Enterprise 9.x/10.x
- Python 3.x (bundled with Splunk)
- A Slack app with a bot token scoped `files:write`, `chat:write`
- A [Perplexity API key](https://www.perplexity.ai/settings/api) (used for the synchronous
  `perplexity_ask`/`perplexity_response` call — see below)
- `Splunk_SA_CIM` (Common Information Model Add-on) — ships by default with every ES install.
  Required for the native Adaptive Response panel status reporting below (the action degrades
  gracefully and still delivers to Slack if it's missing)

## Perplexity API: synchronous ask/response

`param.additional_fields` ships a standing `perplexity_ask` block with three checks run against
every notable: is `$result.repo$` a repo commonly seen for this kind of finding, is
`$result.user$` an expected/authorized user, and is `$result.src$` a low-threat source IP.

When `param.perplexity_enabled` is on (default), `bin/notable_to_perplexity_json.py` answers that
block **in-line, synchronously, before delivery** — a single call to the
[Perplexity Chat Completions API](https://docs.perplexity.ai/) with a JSON schema
`response_format` built from the ask keys plus an `overall` risk read-out. The result is merged
back into the same `additional_fields` object as `perplexity_response`, so it travels through the
exact same paths that already existed:

1. **The same Slack post** (unchanged — still useful for visually auditing exactly what was asked
   and answered).
2. **The same notable comment write-back** (`param.write_back_comment`).
3. **The same KV store enrichment record** (`param.write_back_kvstore`), so the drilldown
   dashboard shows the ask and the answer side by side.

No separate index, credential realm, polling interval, or scripted input is required — the alert
action already has full notable context at send time, so there's nothing to hand off. An earlier
design (`bin/slack_hec_bridge.py`, shipped in 1.3.1–1.3.2) polled Slack asynchronously for a
reply and mapped it onto CIM Risk fields via HEC; it worked, but added a second moving part
(polling interval, thread-ts plumbing, a fixed reply-format contract) to answer questions this
action already had the answer to. It's kept only as a documented "before" lesson — see
[`../SEC1215/lessons/README.md`](../SEC1215/lessons/README.md) for the full write-up of why it
was retired.

## Closing the loop: getting the result back to the analyst

After a successful Slack send, the action writes back to the **same** notable so the analyst
sees the result alongside the rest of the event, without leaving Incident Review:

1. **Adaptive Responses panel** — the action is built on `cim_actions.py`'s `ModularAction`
   class and calls `self.message(..., status='success'/'failure')`. This populates the notable's
   native "Adaptive Responses" section / "View Adaptive Response Invocations" audit trail
   (backed by the `Splunk_Audit.Modular_Actions` data model), typically visible within ~5 minutes.
2. **Notable comment (`param.write_back_comment`, default on)** — the action calls
   `POST /services/notable_update` with `ruleUIDs=<event_id>` and a `comment` summarizing what
   was sent (delivery method, timestamp, `additional_fields`). This is a permanent entry in that
   notable's own Activity timeline, so any analyst who later opens the notable sees it directly —
   this only works when the action runs in a notable context (i.e. `event_id` is present on the
   triggering row) and only supports comment text, not new structured/columnar fields.
3. **KV store enrichment + custom drilldown (`param.write_back_kvstore`, default on)** — see
   below. Gives analysts genuinely structured fields, not just comment text.

### KV store enrichment / custom drilldown

`/services/notable_update` only supports `comment`/`status`/`urgency`/`newOwner`/`disposition` —
no arbitrary new fields. To surface real structured data (delivery status, Slack channel, the
exact `additional_fields` sent, error detail on failure) next to the notable, the action also:

1. Writes a record to the **`notable_slack_enrichment`** KV store collection
   (`default/collections.conf`) via `POST /servicesNS/nobody/<app>/storage/collections/data/...`,
   keyed by **this invocation's `sid`/`rid`** — not `event_id`. That's because Incident Review's
   custom `drilldown_uri` (in `param._cam`) only supports the tokens `$sid$`, `$rid$`, `$time$`,
   `$earliest$`, `$latest$`, `$action_name$` — `event_id` isn't one of them
   ([reference](https://community.splunk.com/t5/Splunk-Search/How-to-change-Custom-Adaptive-response-action-succ-td-p/310960)).
   `event_id`/`orig_sid`/`orig_rid` are still stored on the record for ad hoc `event_id` lookups.
2. Declares `param._cam = {"supports_adhoc": true, "drilldown_uri": "notable_slack_enrichment_drilldown?form.sid=$sid$&form.rid=$rid$", ...}`
   in `alert_actions.conf`. `supports_adhoc` is also what makes the action appear under
   Incident Review's **Run Adaptive Response Actions** ad hoc menu at all
   ([reference](https://community.splunk.com/t5/Splunk-Enterprise-Security/The-quot-Run-Adaptive-Response-Actions-quot-is-not-listing-all/m-p/472638)).
3. Ships a Simple XML view, `default/data/ui/views/notable_slack_enrichment_drilldown.xml`,
   that takes `sid`/`rid` from the drilldown URL and runs
   `| inputlookup notable_slack_enrichment_lookup where sid="$sid$" AND rid="$rid$"` (lookup
   defined in `default/transforms.conf`) to render the record as a table.

From a notable's Adaptive Responses panel, click through this action's entry and you land on
that dashboard with the structured record already loaded — no re-typing tokens.

Adjust `metadata/default.meta`'s `[collections/notable_slack_enrichment]` write ACL if the role
that invokes the action (correlation search owner, or an analyst running it ad hoc) isn't `admin`.

## Testing connectivity / credentials

Both credentials this action depends on — the Slack bot token and the Perplexity API key — can
silently go bad between deployments (rotated, revoked, expired, realm renamed) without anyone
noticing until the next real notable fires and delivery fails. `param.test_connectivity` gives you
a side-effect-free way to check both right now, without needing a real notable or firing any
correlation search.

When `param.test_connectivity = 1`, `bin/notable_to_perplexity_json.py` skips **all** normal
processing — no result rows are read, nothing is posted to Slack, nothing is written back to any
notable comment or KV store record — and instead just resolves and probes each configured
credential:

- **Slack** — calls `auth.test` (no message posted, no file uploaded). Skipped entirely if no
  `param.slack_bot_token`/`param.slack_bot_token_realm` is configured.
- **Perplexity** — sends a minimal 1-token completion request. Skipped if `param.perplexity_enabled`
  is off, or if no `param.perplexity_api_key`/`param.perplexity_api_key_realm` is configured.

Invoke it ad hoc via Splunk's built-in `sendalert` search command — this works from Splunk Web's
Search app, no correlation search required:

```
| makeresults | sendalert notable_to_perplexity_json param.test_connectivity=1
```

Then check `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log` (or run
`index=_internal source=*notable_to_perplexity_json.log*` if that log is being indexed) and grep
for one of these unambiguous outcome lines, one pair per credential:

| Log line prefix | Meaning |
|---|---|
| `SLACK AUTH OK` / `PERPLEXITY AUTH OK` | Credential is valid and the API accepted it |
| `SLACK AUTH FAILURE` / `PERPLEXITY AUTH FAILURE` | Credential is invalid/expired/revoked — this is NOT a transient/network error, the API explicitly rejected it (e.g. `auth.test` returned `ok=false error=invalid_auth`, or Perplexity returned HTTP 401/403) |
| `PERPLEXITY API FAILURE (non-auth)` | Perplexity API reachable and credential fine, but the request failed for another reason (rate limit, bad model name, etc.) |
| `SLACK AUTH SKIPPED` / `PERPLEXITY AUTH SKIPPED` | Nothing configured for that credential (or `perplexity_enabled=0`) — not a failure, just not tested |

Every invocation of the script — with or without `test_connectivity` set, successful or not —
also always logs an unconditional `Invoked: sid=... search_name=... test_connectivity=...
perplexity_enabled=... delivery_method=...` heartbeat line first, so "did the alert action even
run" is never a question you have to guess at from a missing log entry.

The same `SLACK AUTH FAILURE` / `PERPLEXITY AUTH FAILURE` labelling is also used during **real**
notable delivery (not just the test mode) — if a live send fails because Slack rejects the bot
token, or because a `perplexity_ask` call gets a 401/403, the log line makes that unmistakable
rather than burying it in a generic Python traceback.

## Installation

1. Copy this folder to `$SPLUNK_HOME/etc/apps/TA_ResponseActions/`, restart Splunk.
2. Store the Slack bot token in Splunk's credential vault (recommended over plaintext):

   ``` shell
   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=slack_notable_action -d realm=slack_notable_action -d password=xoxb-...
   ```

3. In ES, ensure this app is covered by **Configure > General > App Import** so ES recognizes it
   as an Adaptive Response provider.
4. On a correlation search, **Add New Response Action > Send Notable to Slack (Full JSON)**.
   Configure `slack_channel`, `additional_fields` (JSON, supports `$result.<field>$` /
   `$job.<field>$` tokens), and save.
5. Test via Incident Review → Run Adaptive Response Actions on a notable, or trigger the
   correlation search directly.
6. **(New in 1.3.3)** Store the Perplexity API key in the vault under realm
   `perplexity_notable_action` (same pattern as step 2, different realm name):

   ``` shell
   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=perplexity_notable_action -d realm=perplexity_notable_action \
     -d password=<perplexity_api_key>
   ```

   Get a key at [perplexity.ai/settings/api](https://www.perplexity.ai/settings/api). Alternatively
   set `param.perplexity_api_key` directly on the action (plaintext fallback).

## Files

| Path | Description |
|---|---|
| `default/alert_actions.conf` | Registers the action, delivery/payload parameters, `param._cam` (adhoc + drilldown) |
| `README/alert_actions.conf.spec` | Splunk config spec — drives the auto-generated config UI |
| `bin/notable_to_perplexity_json.py` | Action logic — build payload, vault lookup, Slack delivery, Adaptive Response panel status, notable comment write-back, KV store enrichment write |
| `default/collections.conf` | `notable_slack_enrichment` KV store collection schema |
| `default/transforms.conf` | `notable_slack_enrichment_lookup` — lookup wrapper for reading the collection via SPL |
| `default/data/ui/views/notable_slack_enrichment_drilldown.xml` | Dashboard rendering the enrichment record (including `perplexity_response`) for a given `sid`/`rid` |
| `metadata/default.meta` | Object ACLs |
| `static/appIcon.png`, `appIconAlt.png`, `appIcon_2x.png`, `appIconAlt_2x.png`, `appLogo.png`, `appLogo_2x.png` | App-level icon/logo set (App Manager convention), copied from [`splunk_build`'s `org_template`](https://github.com/UnshakeableSaltLtd/splunk_build/tree/main/library/unshakeablesalt/org_template/static) |
| `appserver/static/appIcon.png` | Icon referenced by `alert_actions.conf`'s `icon_path = appIcon.png` for the action's UI icon in Incident Review |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_perplexity_json.log`

## Release Notes

### 1.3.4

- Added `param.test_connectivity` — a side-effect-free credential check mode (see "Testing
  connectivity / credentials" above). Skips all real processing and just probes Slack
  (`auth.test`) and Perplexity (a minimal 1-token completion), logging unambiguous
  `SLACK/PERPLEXITY AUTH OK` / `AUTH FAILURE` / `AUTH SKIPPED` lines. Invoke via
  `| makeresults | sendalert notable_to_perplexity_json param.test_connectivity=1`.
- Added `SlackApiError` and `PerplexityApiError` exception classes (each with an `is_auth_error`
  flag) so a bad/expired/revoked credential is now always distinguishable in the log from a
  generic network/timeout/parse error, both in the new test mode and during normal delivery.
- Added `resolve_slack_bot_token()` / `resolve_perplexity_api_key()` helpers that centralize the
  vault-vs-plaintext credential lookup (previously duplicated inline in `main()`) and report a
  clear "source" string (`vault realm=...` / `plaintext` / `not configured`) in every related log
  line.
- `get_perplexity_response()` now logs a distinct `PERPLEXITY AUTH FAILURE` line for HTTP
  401/403 versus `PERPLEXITY API FAILURE` for other errors (rate limits, network issues, response
  parsing failures), instead of one generic `log.exception(...)` for every case.
- Every invocation now logs an unconditional `Invoked: sid=... search_name=...
  test_connectivity=... perplexity_enabled=... delivery_method=...` heartbeat line immediately
  after parsing configuration, regardless of outcome.
- The real Slack delivery failure path now detects `SlackApiError` and logs a distinct
  `SLACK AUTH FAILURE` line (with the failing method + Slack error code) when the token itself is
  the problem, in addition to the existing generic failure logging for non-auth errors.

### 1.3.3

- **Replaced the Slack → HEC bridge (`bin/slack_hec_bridge.py`, 1.3.1–1.3.2) with a synchronous
  Perplexity API call made in-line inside `bin/notable_to_perplexity_json.py`.** The bridge script,
  its `inputs.conf`/`inputs.conf.spec` registration, and the KV store/collections/transforms/
  drilldown fields it added (`slack_thread_ts`, `awaiting_ai_response`, `risk_object`,
  `risk_object_type`, `risk_score`, `risk_message`, `hec_sent`, `notable_enriched_at`) have all
  been removed from this app and archived as a documented lesson at
  [`../SEC1215/lessons/`](../SEC1215/lessons/README.md).
- Added `param.perplexity_enabled`, `param.perplexity_api_key_realm`, `param.perplexity_api_key`,
  and `param.perplexity_model` to `alert_actions.conf`. When enabled,
  `bin/notable_to_perplexity_json.py` answers the standing `perplexity_ask` block via the Perplexity
  API before delivery and merges the result into `additional_fields.perplexity_response` — see
  "Perplexity API: synchronous ask/response" above.
- Removed the `reply_format` key from the default `perplexity_ask` block in
  `param.additional_fields` (no longer needed — the synchronous call uses a proper JSON Schema
  `response_format` instead of instructing the model to reply with raw JSON text in Slack).
- Slack delivery itself is unchanged — still useful for visually auditing what was asked and
  answered.

### 1.3.2

- Fixed `README/alert_actions.conf.spec` for `[notable_to_perplexity_json]`: added the missing
  `param._cam` documentation line. Splunk's own dev docs say `param._cam` is inherited from
  `Splunk_SA_CIM`'s spec and doesn't need redeclaring, but any tooling that only resolves specs
  on a per-app basis (rather than merging in other installed apps' specs) will otherwise flag it.
- Added app icon/logo assets (`static/appIcon.png`, `appIconAlt.png`, `appIcon_2x.png`,
  `appIconAlt_2x.png`, `appLogo.png`, `appLogo_2x.png`) plus `appserver/static/appIcon.png`,
  reused from [`splunk_build`'s `org_template`](https://github.com/UnshakeableSaltLtd/splunk_build/tree/main/library/unshakeablesalt/org_template/static).
  This satisfies `alert_actions.conf`'s `icon_path = appIcon.png` setting, which per Splunk's own
  spec "refers to the `appserver/static` directory in the app that the alert action is defined in."
- **Note on the VS Code Splunk extension linter:** the official
  [Visual Studio Code Extension for Splunk](https://github.com/splunk/vscode-extension-splunk) only
  validates `.conf` files against its own bundled global spec files (or a single folder set via the
  `splunk.spec.FilePath` setting) — it never reads an app's own `README/*.conf.spec` file
  (confirmed in `extension.js`'s `getSpecFilePath()`, and tracked as a known gap for `inputs.conf` in
  [issue #59](https://github.com/splunk/vscode-extension-splunk/issues/59), which applies to every
  conf type). That means every custom `param.*` key on a custom alert action — including
  `param._cam` — will always show as "Invalid key in stanza" in that extension, regardless of what's
  declared in this app's spec file. This is a known limitation of the extension, not a defect in this
  app; these specific warnings are safe to ignore. (Community reports of the same `param._cam`
  warning, e.g. [Splunk Add-on Builder thread](https://community.splunk.com/t5/All-Apps-and-Add-ons/Splunk-Add-on-Builder-How-to-resolve-quot-Invalid-key-in-stanza/m-p/215990)
  and [VictorOps app thread](https://community.splunk.com/t5/Splunk-On-Call/Invalid-key-in-stanza/m-p/477090),
  confirm the same root cause.)

### 1.3.1

- Added `bin/slack_hec_bridge.py`, a classic scripted input (`default/inputs.conf`,
  `README/inputs.conf.spec`) that closes the Phase 2/3 agentic loop: polls the KV store for
  `awaiting_ai_response=1` records, reads the AI's reply from the Slack thread, parses it against
  the strict JSON schema, POSTs a CIM Risk event to HEC (`index=risk` by default), and writes the
  verdict back to the originating notable's comment trail. See
  [../SEC1215/ARCHITECTURE.md](../SEC1215/ARCHITECTURE.md) for the full narrative.
- `alert_actions.conf`'s default `perplexity_ask.additional_fields` block now also ships a
  `reply_format` key that pins the AI to a fixed JSON reply shape
  (`risk_score`/`risk_object`/`risk_object_type`/`risk_message`), so `slack_hec_bridge.py` can
  parse it deterministically instead of scraping free-text prose.
- `bin/notable_to_perplexity_json.py` now resolves the Slack channel + message `ts` of the uploaded
  file via `files.info` (file_upload delivery only) and stores it as `slack_thread_ts` on the
  KV store record, with `awaiting_ai_response=1`, so the bridge knows which thread to poll.
- `default/collections.conf`/`transforms.conf` extended with `slack_thread_ts`,
  `awaiting_ai_response`, `risk_object`, `risk_object_type`, `risk_score`, `risk_message`,
  `hec_sent`, `notable_enriched_at`; the drilldown dashboard gained a new "Agentic AI verdict"
  panel showing them.
- **Known limitation:** the bridge only works for `delivery_method=file_upload` — webhook
  delivery has no bot token/`conversations.read` scope to read a reply back with.

### 1.3.0

- `param.additional_fields` now ships a default `perplexity_ask` block with three standing checks
  run against every notable by the Slack->HEC bridge automation: is `$result.repo$` a repo we
  commonly see for this kind of finding, is `$result.user$` an expected/authorized user, and is
  `$result.src$` a low-threat source IP. Override or extend per correlation search as needed.
- Slack `initial_comment`/webhook summary text (both delivery methods) now reads
  `Notable - <search_name>` / `Event time: <event time>` ahead of the JSON payload, instead of the
  old `:rotating_light:`/SID-only line. Event time is read from the notable's own `_time` field
  where available, falling back to the send timestamp.

### 1.2.0

- Added `param.write_back_kvstore` — persists a structured enrichment record (event_id, delivery
  method, Slack channel, `additional_fields` JSON, status/error) to a new `notable_slack_enrichment`
  KV store collection, keyed by the AR invocation's `sid`/`rid`.
- Added `param._cam` to `alert_actions.conf`: `supports_adhoc: true` (makes the action available
  under Incident Review's "Run Adaptive Response Actions" ad hoc menu) and a `drilldown_uri`
  pointing at a new custom dashboard.
- Added `default/collections.conf`, `default/transforms.conf`, and
  `default/data/ui/views/notable_slack_enrichment_drilldown.xml` for the KV store lookup + view.
- Fixed a repo-level `.gitignore` bug (a leftover PyInstaller `*.spec` rule) that was silently
  excluding Splunk's `.conf.spec` convention files from commits.

### 1.1.0

- Added native Incident Review "Adaptive Responses" panel reporting via `cim_actions.ModularAction.message()`.
- Added `param.write_back_comment` — posts a comment back to the triggering notable via
  `/services/notable_update` so the collected Slack data appears in that notable's own Activity
  timeline for analysts.

### 1.0.0

- Initial release: full-JSON notable delivery to Slack via bot token (file_upload) or webhook,
  configurable additional fields, credential vault support, field denylist.

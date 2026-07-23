# TA_ResponseActions

**App Name:** Notable to Slack (Full JSON)
**Version:** 1.3.1
**Author:** David Pollard, Unshakeable Salt Ltd
**Associated Session:** [SEC1215 — From Zero to Agentic](../SEC1215/README.md)

## Overview

Custom Splunk Enterprise Security **Adaptive Response Action** that sends the triggering
Notable/Finding to Slack as a complete JSON payload — every CIM/risk/notable field, plus
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
- A Slack app with a bot token scoped `files:write`, `chat:write`, and `conversations.replies`/
  `channels:history` (the last two are needed by `bin/slack_hec_bridge.py`, see below, to read the
  agentic AI's reply out of the thread — file_upload delivery only, see "Known limitation")
- A Splunk HEC token with write scope to the CIM Risk index (`index=risk` by default)
- `Splunk_SA_CIM` (Common Information Model Add-on) — ships by default with every ES install.
  Required for the native Adaptive Response panel status reporting below (the action degrades
  gracefully and still delivers to Slack if it's missing)

## Phase 2/3: closing the agentic loop (`bin/slack_hec_bridge.py`)

As of 1.3.1, a second component — `bin/slack_hec_bridge.py`, registered as a classic scripted
input in `default/inputs.conf` — completes the three-phase agentic loop described in
[../SEC1215/ARCHITECTURE.md](../SEC1215/ARCHITECTURE.md):

1. **Phase 1** (this action, above) sends the notable to Slack and asks the agentic AI
   (`@perplexity_ask`) a question with a strict JSON `reply_format` pinned in
   `alert_actions.conf`, then records `slack_thread_ts`/`awaiting_ai_response=1` in the
   `notable_slack_enrichment` KV store record — **file_upload delivery only** (see "Known
   limitation" below).
2. **Phase 2** — every 60 seconds, `slack_hec_bridge.py` polls the KV store for
   `awaiting_ai_response=1` records, reads the Slack thread for the AI's reply, parses it against
   that same JSON schema, and maps it onto the CIM Risk data model's minimum fields
   (`risk_object`, `risk_object_type`, `risk_score`, `risk_message`). It then POSTs that as an HEC
   event into `index=risk` (configurable via `risk_index` in `inputs.conf`) — this is what makes
   the verdict CIM-compliant and re-injectable into ES's own Risk Analysis framework.
3. **Phase 3** — the bridge writes the same verdict back to the *originating* notable via
   `/services/notable_update` (comment only — that API can't accept new fields) and updates the KV
   store record (`hec_sent`, `notable_enriched_at`), so an analyst opening either the notable or the
   drilldown dashboard sees the verdict without anyone having copied it there by hand.

**Known limitation:** only notables delivered via `delivery_method=file_upload` can be bridged.
Webhook delivery has no bot token and no `conversations.read` scope, so there's no way to read a
reply back — a correlation search wired to webhook delivery will silently never get Phase 2/3
enrichment. See Takeaway 3's pitfalls in `../SEC1215/ARCHITECTURE.md` for this and other trade-offs
(reply-format drift, and choosing a classic scripted input over a full modular input scheme).

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

## Installation

1. Copy this folder to `$SPLUNK_HOME/etc/apps/TA_ResponseActions/`, restart Splunk.
2. Store the Slack bot token in Splunk's credential vault (recommended over plaintext):
   ```
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
6. **(New in 1.3.1)** Store the HEC token in the vault under a *new* realm, `hec_risk_bridge`
   (same pattern as step 2, different realm name):
   ```
   curl -k https://localhost:8089/servicesNS/nobody/TA_ResponseActions/storage/passwords \
     -u admin:<pass> -d name=hec_risk_bridge -d realm=hec_risk_bridge -d password=<hec_token>
   ```
   Confirm that token has write scope to your risk index (default `risk`) before proceeding.
7. **(New in 1.3.1)** Set `hec_url` in `local/inputs.conf` (copy the `[script://./bin/slack_hec_bridge.py]`
   stanza from `default/inputs.conf` and override `hec_url`, and `risk_index` if not using the
   default `risk` index). Restart Splunk, or wait up to 60s, and confirm
   `$SPLUNK_HOME/var/log/splunk/slack_hec_bridge.log` shows polling activity with no errors.

## Files

| Path | Description |
|---|---|
| `default/alert_actions.conf` | Registers the action, delivery/payload parameters, `param._cam` (adhoc + drilldown) |
| `README/alert_actions.conf.spec` | Splunk config spec — drives the auto-generated config UI |
| `bin/notable_to_slack_json.py` | Action logic — build payload, vault lookup, Slack delivery, Adaptive Response panel status, notable comment write-back, KV store enrichment write |
| `default/collections.conf` | `notable_slack_enrichment` KV store collection schema |
| `default/transforms.conf` | `notable_slack_enrichment_lookup` — lookup wrapper for reading the collection via SPL |
| `default/data/ui/views/notable_slack_enrichment_drilldown.xml` | Dashboard rendering the enrichment record for a given `sid`/`rid`, including the Phase 2/3 verdict columns |
| `bin/slack_hec_bridge.py` | Phase 2/3 bridge — polls the KV store, reads the AI's Slack reply, writes a CIM Risk HEC event, enriches the originating notable |
| `default/inputs.conf` | Registers `slack_hec_bridge.py` as a classic scripted input; custom keys are self-parsed, not delivered by splunkd |
| `README/inputs.conf.spec` | Documentation-only spec for the `inputs.conf` custom keys |
| `metadata/default.meta` | Object ACLs |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log` and `$SPLUNK_HOME/var/log/splunk/slack_hec_bridge.log`

## Release Notes

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
- `bin/notable_to_slack_json.py` now resolves the Slack channel + message `ts` of the uploaded
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

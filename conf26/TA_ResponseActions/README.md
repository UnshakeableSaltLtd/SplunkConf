# TA_ResponseActions

**App Name:** Notable to Slack (Full JSON)
**Version:** 1.1.0
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
- A Slack app with a bot token scoped `files:write`, `chat:write` (for file_upload), or an
  Incoming Webhook URL (for webhook mode)
- `Splunk_SA_CIM` (Common Information Model Add-on) — ships by default with every ES install.
  Required for the native Adaptive Response panel status reporting below (the action degrades
  gracefully and still delivers to Slack if it's missing)

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

If you need genuinely new structured fields visible as columns in Incident Review (rather than
comment text), that requires a separate pattern — e.g. a lookup/KV store keyed by `event_id`
joined into a custom drilldown panel — which is out of scope for this action.

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

## Files

| Path | Description |
|---|---|
| `default/alert_actions.conf` | Registers the action, delivery/payload parameters |
| `README/alert_actions.conf.spec` | Splunk config spec — drives the auto-generated config UI |
| `bin/notable_to_slack_json.py` | Action logic — build payload, vault lookup, Slack delivery, Adaptive Response panel status, notable comment write-back |
| `metadata/default.meta` | Object ACLs |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log`

## Release Notes

### 1.1.0

- Added native Incident Review "Adaptive Responses" panel reporting via `cim_actions.ModularAction.message()`.
- Added `param.write_back_comment` — posts a comment back to the triggering notable via
  `/services/notable_update` so the collected Slack data appears in that notable's own Activity
  timeline for analysts.

### 1.0.0

- Initial release: full-JSON notable delivery to Slack via bot token (file_upload) or webhook,
  configurable additional fields, credential vault support, field denylist.

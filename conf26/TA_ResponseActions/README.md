# TA_ResponseActions

**App Name:** Notable to Slack (Full JSON)
**Version:** 1.0.0
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
| `bin/notable_to_slack_json.py` | Action logic — build payload, vault lookup, Slack delivery |
| `metadata/default.meta` | Object ACLs |

Logs: `$SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log`

## Release Notes

### 1.0.0

- Initial release: full-JSON notable delivery to Slack via bot token (file_upload) or webhook,
  configurable additional fields, credential vault support, field denylist.

[notable_to_slack_json]
param.delivery_method = <string> "file_upload" or "webhook". file_upload sends the complete JSON with
  no size cap via a Slack bot token; webhook is quicker to set up but truncates large payloads.
  Default: file_upload

param.slack_webhook_url = <string> Slack Incoming Webhook URL. Only used when delivery_method=webhook.

param.slack_bot_token_realm = <string> Name of the credential realm in Splunk's storage/passwords
  vault that holds the Slack bot token (xoxb-...). Recommended over storing the token in plaintext.

param.slack_bot_token = <string> Plaintext fallback for the Slack bot token. Leave blank if using
  slack_bot_token_realm. Only used when delivery_method=file_upload.

param.slack_channel = <string> Slack channel ID (e.g. C0123ABCD) to post/upload the notable JSON to.
  Only used when delivery_method=file_upload.

param.additional_fields = <string> JSON object of extra fields to merge into the outgoing payload
  under "additional_fields". Supports $result.<field>$ and $job.<field>$ tokens, which are
  substituted per-event before the JSON is parsed. Example:
  {"environment": "prod-uk1", "runbook": "https://wiki.internal/notable/$result.rule_id$"}

param.field_denylist = <string> Comma-separated list of field names to remove from the notable
  before it is sent to Slack.

param.include_raw_event = <bool> Whether to include the _raw event text in the payload. Default: 0

param.pretty_print = <bool> Whether to indent the JSON for readability. Default: 1

param.max_events = <number> Maximum number of result rows to send per invocation. Default: 5

param.write_back_comment = <bool> Whether to POST a comment back to the triggering notable
  (via /services/notable_update, matched by event_id) after a successful Slack send, so the
  collected data appears in that notable's own Activity timeline in Incident Review. Requires
  the action to be invoked in a notable context (event_id present in the result row). Default: 1

param.write_back_kvstore = <bool> Whether to persist a structured record (event_id, delivery
  details, additional_fields JSON, status/error) to the notable_slack_enrichment KV store
  collection, keyed by this invocation's sid/rid. Surfaced to analysts via the drilldown_uri
  configured in param._cam - use this when you need real structured fields next to the notable,
  not just comment text. Default: 1

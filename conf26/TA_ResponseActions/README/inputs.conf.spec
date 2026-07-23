# This is a documentation-only spec for default/inputs.conf's
# [script://./bin/slack_hec_bridge.py] stanza (Phase 2/3 bridge - see
# ../SEC1215/ARCHITECTURE.md). It is intentionally a classic scripted
# input, not a splunklib.modularinput scheme, so the custom keys below
# are NOT delivered by splunkd's own modular-input protocol - they are
# self-parsed by bin/slack_hec_bridge.py reading this same inputs.conf
# stanza directly via Python's configparser. That means Splunk Web will
# NOT auto-generate a settings UI for these keys the way it would for a
# proper modular input; edit local/inputs.conf directly. This trade-off
# is documented as a pitfall for Takeaway 3 in ../SEC1215/ARCHITECTURE.md.

[script://<path to slack_hec_bridge.py>]
* Standard scripted input stanza. See inputs.conf.spec in Splunk's own
  system default for the full set of universal scripted-input keys
  (disabled, interval, index, python.version, passAuth, etc).

passAuth = splunk-system-user
* Required. Makes splunkd append a local session key as the last argv
  element on every invocation, so the script can call splunkd's REST
  API (KV store, notable_update) without a separate login step.

interval = <number>
* How often, in seconds, to run the poll pass. Default: 60

risk_index = <string>
* Splunk index that receives the CIM Risk event via HEC. The HEC token
  in hec_token_realm must have write scope to this index. Default: risk

hec_url = <string>
* Full HEC collector URL for this Splunk instance, e.g.
  https://splunk-hec.internal.example.com:8088. The script appends
  /services/collector/event itself if not already present. Required -
  no default.

hec_token_realm = <string>
* Name of the credential realm in Splunk's storage/passwords vault that
  holds the HEC token used for risk_index writes. Create it the same
  way as slack_notable_action (see the app's README.md installation
  steps). Default: hec_risk_bridge

slack_bot_token_realm = <string>
* Name of the credential realm holding the Slack bot token used to read
  thread replies via conversations.replies. Reuses the same realm as
  the file_upload delivery path documented in alert_actions.conf.spec.
  Default: slack_notable_action

#!/usr/bin/env python3
"""
slack_hec_bridge.py
--------------------------------------------------------------------
Phase 2/3 of the three-phase agentic loop described in
../SEC1215/ARCHITECTURE.md:

  Phase 1 (v1.2.0/v1.3.0, bin/notable_to_slack_json.py):
      ES correlation search -> Adaptive Response -> Slack (file_upload),
      with the agentic AI (@perplexity_ask) asked a structured question
      in-thread, and a KV-store enrichment record left behind carrying
      slack_thread_ts / awaiting_ai_response=1.

  Phase 2 (this script):
      Poll the KV store for awaiting_ai_response=1 records, read the
      Slack thread for the AI's reply, parse it against the strict JSON
      reply_format pinned in default/alert_actions.conf, and map it onto
      the CIM Risk data model's minimum fields (risk_object,
      risk_object_type, risk_score, risk_message). POST that as an HEC
      event into index=risk - this is what makes it CIM-compliant and
      re-injectable into ES's own Risk Analysis framework, not a
      bolted-on side channel.
      https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/riskanalysisframework

  Phase 3 (this script):
      Land the same verdict where a SOC analyst is already looking - the
      ORIGINATING notable's own Activity trail (via /services/notable_update
      comment, since that API cannot accept new indexed fields) and the KV
      store record used by the drilldown dashboard. No human triggers any
      of this; the loop is: alert fires -> AI asked -> AI replies -> risk
      index gets a row -> notable gets a comment.

Design choice - classic scripted input, not a modular input:
  This is registered in default/inputs.conf as a plain [script://...]
  stanza (interval=60, passAuth=splunk-system-user), NOT a full
  splunklib.modularinput scheme. Splunk does not deliver custom stanza
  keys to classic scripted inputs the way it does for modular inputs, so
  this script re-reads its OWN stanza out of $SPLUNK_HOME/etc/apps/.../
  {default,local}/inputs.conf via configparser instead. That is a
  deliberate simplification for an internal poller (see Takeaway 3
  pitfalls in ARCHITECTURE.md for the trade-off: no auto-generated
  Splunk Web config UI for these settings).

  splunkd appends a session key as the LAST sys.argv element when
  passAuth=splunk-system-user is set, so this script gets a session key
  for free without a separate login call.
  https://docs.splunk.com/Documentation/Splunk/latest/AdvancedDev/ScriptedInputCredentials

Install at:
  $SPLUNK_HOME/etc/apps/TA_ResponseActions/bin/slack_hec_bridge.py
--------------------------------------------------------------------
"""
import configparser
import json
import logging
import logging.handlers
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP_NAME = "slack_hec_bridge"
KVSTORE_APP = "TA_ResponseActions"
KVSTORE_COLLECTION = "notable_slack_enrichment"

_SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
_APP_DIR = os.path.join(_SPLUNK_HOME, "etc", "apps", KVSTORE_APP)


# ----------------------------------------------------------------------
# Logging - writes to $SPLUNK_HOME/var/log/splunk/slack_hec_bridge.log
# ----------------------------------------------------------------------
def setup_logging():
    log_dir = os.path.join(_SPLUNK_HOME, "var", "log", "splunk")
    logger = logging.getLogger(APP_NAME)
    logger.setLevel(logging.INFO)
    try:
        handler = logging.handlers.RotatingFileHandler(
            os.path.join(log_dir, f"{APP_NAME}.log"), maxBytes=5_000_000, backupCount=3
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    except Exception:
        logging.basicConfig(level=logging.INFO)
    return logger


log = setup_logging()


# ----------------------------------------------------------------------
# Self-parse this script's OWN [script://./bin/slack_hec_bridge.py]
# stanza out of inputs.conf (local/ overrides default/), since classic
# scripted inputs don't get custom keys delivered by splunkd the way
# modular inputs do. See module docstring.
# ----------------------------------------------------------------------
def load_stanza_config():
    parser = configparser.ConfigParser()
    default_conf = os.path.join(_APP_DIR, "default", "inputs.conf")
    local_conf = os.path.join(_APP_DIR, "local", "inputs.conf")
    parser.read([default_conf, local_conf])  # local/ overrides default/ if present

    stanza = None
    for section in parser.sections():
        if section.startswith("script://") and "slack_hec_bridge.py" in section:
            stanza = section
            break
    if stanza is None:
        raise RuntimeError(
            "Could not find a [script://.../slack_hec_bridge.py] stanza in "
            f"{default_conf} or {local_conf}"
        )

    cfg = dict(parser.items(stanza))
    cfg.setdefault("risk_index", "risk")
    cfg.setdefault("hec_token_realm", "hec_risk_bridge")
    cfg.setdefault("slack_bot_token_realm", "slack_notable_action")
    if not cfg.get("hec_url"):
        raise RuntimeError(f"hec_url is not set in the [{stanza}] stanza")
    return cfg


# ----------------------------------------------------------------------
# splunkd appends the session key as the LAST argv element when
# passAuth=splunk-system-user is configured for this scripted input.
# ----------------------------------------------------------------------
def get_session_key():
    if len(sys.argv) < 2:
        raise RuntimeError(
            "No session key on argv; is passAuth=splunk-system-user set in inputs.conf?"
        )
    return sys.argv[-1].strip()


def get_server_uri():
    # splunkd's own management port on the local instance.
    return os.environ.get("SPLUNK_URI") or "https://127.0.0.1:8089"


def _unverified_ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


# ----------------------------------------------------------------------
# Vault lookup - same pattern as notable_to_slack_json.get_secret_from_vault,
# duplicated here so this script has no import-time dependency on the
# adaptive response action module (they are invoked by two very different
# Splunk subsystems - alert action vs. scripted input - and are versioned
# independently even though they ship in the same app).
# ----------------------------------------------------------------------
def get_secret_from_vault(server_uri, session_key, realm, app=KVSTORE_APP):
    url = (
        f"{server_uri}/servicesNS/nobody/{app}/storage/passwords"
        f"?output_mode=json&count=0&search=realm%3D{urllib.parse.quote(realm)}"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
    with urllib.request.urlopen(req, timeout=15, context=_unverified_ssl_context()) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    for entry in data.get("entry", []):
        content = entry.get("content", {})
        if content.get("realm") == realm:
            return content.get("clear_password")
    return None


# ----------------------------------------------------------------------
# KV store: find records awaiting an AI reply
# ----------------------------------------------------------------------
def query_pending_records(server_uri, session_key, app=KVSTORE_APP):
    query = urllib.parse.quote(json.dumps({"awaiting_ai_response": 1}))
    url = (
        f"{server_uri}/servicesNS/nobody/{app}/storage/collections/data/"
        f"{KVSTORE_COLLECTION}?query={query}&output_mode=json"
    )
    req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
    with urllib.request.urlopen(req, timeout=15, context=_unverified_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


def update_kvstore_record(server_uri, session_key, key, fields, app=KVSTORE_APP):
    url = (
        f"{server_uri}/servicesNS/nobody/{app}/storage/collections/data/"
        f"{KVSTORE_COLLECTION}/{urllib.parse.quote(key)}"
    )
    body = json.dumps(fields).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Splunk {session_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15, context=_unverified_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ----------------------------------------------------------------------
# Notable write-back (Phase 3) - duplicated small helper, same rationale
# as get_secret_from_vault above and same API-shape constraint documented
# in notable_to_slack_json.post_comment_to_notable: only comment/status/
# urgency/newOwner/disposition are writable, no new fields.
# ----------------------------------------------------------------------
def post_comment_to_notable(server_uri, session_key, event_id, comment):
    url = f"{server_uri}/services/notable_update"
    body = urllib.parse.urlencode({"ruleUIDs": event_id, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Authorization": f"Splunk {session_key}"}
    )
    with urllib.request.urlopen(req, timeout=15, context=_unverified_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ----------------------------------------------------------------------
# Slack: look for a reply from a real (non-bot) user in the thread
# ----------------------------------------------------------------------
def get_latest_human_reply(token, channel, thread_ts):
    url = f"https://slack.com/api/conversations.replies?{urllib.parse.urlencode({'channel': channel, 'ts': thread_ts})}"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {token}"}, method="GET")
    with urllib.request.urlopen(req, timeout=30) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    if not data.get("ok"):
        log.warning("conversations.replies failed for channel=%s ts=%s: %s", channel, thread_ts, data)
        return None
    messages = data.get("messages") or []
    # messages[0] is the original bot message (the uploaded file); any
    # later message not from a bot is a candidate AI/analyst reply.
    for msg in messages[1:]:
        if not msg.get("bot_id"):
            return msg.get("text", "")
    return None


# ----------------------------------------------------------------------
# Parse the strict reply_format pinned in alert_actions.conf's
# perplexity_ask.reply_format prompt. Tolerates the AI wrapping the JSON
# in a code fence or adding stray whitespace, but does NOT try to
# salvage free text that isn't valid JSON - that drift is exactly the
# pitfall documented under Takeaway 3 in ARCHITECTURE.md, and papering
# over it here would hide the failure mode we want the talk to surface.
# ----------------------------------------------------------------------
def parse_verdict(reply_text):
    if not reply_text:
        return None
    text = reply_text.strip()
    if text.startswith("```"):
        text = text.strip("`")
        if text.lower().startswith("json"):
            text = text[4:]
        text = text.strip()
    try:
        verdict = json.loads(text)
    except json.JSONDecodeError:
        log.warning("Could not parse AI reply as JSON, reply_format drift: %r", reply_text)
        return None

    try:
        risk_score = int(verdict.get("risk_score"))
    except (TypeError, ValueError):
        log.warning("AI reply JSON missing/invalid risk_score: %r", verdict)
        return None
    risk_score = max(0, min(100, risk_score))

    risk_object = str(verdict.get("risk_object") or "").strip()
    risk_object_type = str(verdict.get("risk_object_type") or "other").strip().lower()
    if risk_object_type not in ("user", "system", "other"):
        risk_object_type = "other"
    if not risk_object:
        log.warning("AI reply JSON missing risk_object: %r", verdict)
        return None

    return {
        "risk_object": risk_object,
        "risk_object_type": risk_object_type,
        "risk_score": risk_score,
        "risk_message": str(verdict.get("risk_message") or "").strip(),
    }


# ----------------------------------------------------------------------
# HEC: write the CIM Risk event. This is the step that makes the
# agentic AI's verdict re-injectable into Splunk ES's own Risk Analysis
# framework rather than living only in Slack/KV store - any correlation
# search or Risk Notable that already reads from index=risk picks this
# up with no further code, fully agentic (no analyst has to copy a
# number anywhere).
# https://dev.splunk.com/view/enterprise-security/SP-CAAAFBM
# ----------------------------------------------------------------------
def send_hec_risk_event(hec_url, hec_token, risk_index, verdict, source_event_id):
    event = {
        "sourcetype": "stash_risk",
        "index": risk_index,
        "event": {
            "risk_object": verdict["risk_object"],
            "risk_object_type": verdict["risk_object_type"],
            "risk_score": verdict["risk_score"],
            "risk_message": verdict["risk_message"] or "Agentic AI verdict via slack_hec_bridge.py",
            "description": verdict["risk_message"] or "Agentic AI verdict via slack_hec_bridge.py",
            "source": "slack_hec_bridge",
            "orig_event_id": source_event_id,
        },
    }
    body = json.dumps(event).encode("utf-8")
    req = urllib.request.Request(
        hec_url,
        data=body,
        method="POST",
        headers={"Authorization": f"Splunk {hec_token}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=30, context=_unverified_ssl_context()) as resp:
        return json.loads(resp.read().decode("utf-8"))


# ----------------------------------------------------------------------
# Main poll loop (single pass - splunkd re-invokes this every `interval`
# seconds per inputs.conf, so no internal sleep/loop is needed).
# ----------------------------------------------------------------------
def main():
    cfg = load_stanza_config()
    session_key = get_session_key()
    server_uri = get_server_uri()

    risk_index = cfg.get("risk_index", "risk")
    hec_url = cfg["hec_url"].rstrip("/")
    if not hec_url.endswith("/services/collector/event"):
        hec_url = f"{hec_url}/services/collector/event"

    hec_token = get_secret_from_vault(server_uri, session_key, cfg["hec_token_realm"])
    slack_token = get_secret_from_vault(server_uri, session_key, cfg["slack_bot_token_realm"])
    if not hec_token:
        log.error("No HEC token found in vault realm=%s; cannot proceed", cfg["hec_token_realm"])
        sys.exit(1)
    if not slack_token:
        log.error("No Slack bot token found in vault realm=%s; cannot proceed", cfg["slack_bot_token_realm"])
        sys.exit(1)

    try:
        pending = query_pending_records(server_uri, session_key)
    except Exception:
        log.exception("Failed to query KV store for pending records")
        sys.exit(1)

    log.info("Polling %d pending record(s) for an AI reply", len(pending))

    for record in pending:
        key = record.get("_key")
        channel = record.get("slack_channel")
        thread_ts = record.get("slack_thread_ts")
        event_id = record.get("event_id")
        if not (key and channel and thread_ts):
            log.warning("Skipping malformed pending record: %s", record)
            continue

        try:
            reply_text = get_latest_human_reply(slack_token, channel, thread_ts)
        except Exception:
            log.exception("Failed to fetch replies for key=%s channel=%s ts=%s", key, channel, thread_ts)
            continue

        if reply_text is None:
            log.debug("No reply yet for key=%s; will re-check next interval", key)
            continue

        verdict = parse_verdict(reply_text)
        if verdict is None:
            # reply_format drift (Takeaway 3 pitfall): log it, leave the
            # record awaiting_ai_response=1 so a human can still see the
            # raw reply in the thread, but don't crash the poll loop.
            log.warning("Reply for key=%s did not match reply_format; leaving pending", key)
            continue

        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

        try:
            send_hec_risk_event(hec_url, hec_token, risk_index, verdict, event_id)
            hec_sent = 1
        except Exception:
            log.exception("Failed to POST HEC risk event for key=%s", key)
            hec_sent = 0

        if event_id:
            try:
                post_comment_to_notable(
                    server_uri,
                    session_key,
                    event_id,
                    f"Agentic AI verdict via slack_hec_bridge.py: "
                    f"risk_object={verdict['risk_object']} "
                    f"risk_object_type={verdict['risk_object_type']} "
                    f"risk_score={verdict['risk_score']}. "
                    f"{verdict['risk_message']}".strip(),
                )
            except Exception:
                log.exception("Failed to write comment back to notable event_id=%s", event_id)

        try:
            update_kvstore_record(
                server_uri,
                session_key,
                key,
                {
                    **record,
                    "risk_object": verdict["risk_object"],
                    "risk_object_type": verdict["risk_object_type"],
                    "risk_score": verdict["risk_score"],
                    "risk_message": verdict["risk_message"],
                    "hec_sent": hec_sent,
                    "notable_enriched_at": now,
                    "awaiting_ai_response": 0,
                },
            )
        except Exception:
            log.exception("Failed to update KV store record key=%s with verdict", key)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        log.exception("slack_hec_bridge.py failed")
        sys.exit(1)

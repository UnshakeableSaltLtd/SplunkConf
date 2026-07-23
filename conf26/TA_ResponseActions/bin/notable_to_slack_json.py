#!/usr/bin/env python3
"""
notable_to_slack_json.py
--------------------------------------------------------------------
Splunk Enterprise Security custom Adaptive Response Action.

Sends the triggering Notable/Finding to Slack as a *complete* JSON
payload (all CIM/risk/notable fields), merged with any user-defined
additional fields configured on the action.

After delivery, the action also writes back to the SAME notable so
analysts see the result alongside the rest of the event in Incident
Review:
  1. cim_actions.ModularAction.message() -> native "Adaptive Responses"
     panel / "View Adaptive Response Invocations" audit trail.
  2. /services/notable_update comment -> a permanent entry in that
     notable's own Activity/comment timeline (the collected Slack data).

Install at:
  $SPLUNK_HOME/etc/apps/TA_ResponseActions/bin/notable_to_slack_json.py

Contract: Splunk invokes this script as:
  notable_to_slack_json.py --execute
and writes the alert configuration payload (JSON) to stdin.
See: https://dev.splunk.com/enterprise/docs/devtools/customalertactions/writescriptcaa
--------------------------------------------------------------------
"""
import csv
import gzip
import json
import logging
import logging.handlers
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

APP_NAME = "notable_to_slack_json"
TOKEN_RE = re.compile(r"\$(result|job)\.([A-Za-z0-9_.]+)\$")

# ----------------------------------------------------------------------
# Optional: Splunk_SA_CIM's ModularAction gives us the native Incident
# Review "Adaptive Responses" panel + "View Adaptive Response Invocations"
# audit trail for free, via self.message(). Splunk_SA_CIM (the Common
# Information Model Add-on) ships by default with every Splunk ES
# install, but we degrade gracefully - Slack delivery still works even
# if it's missing on a non-ES search head.
# https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/adaptiveresponseframework/
# ----------------------------------------------------------------------
_SPLUNK_HOME = os.environ.get("SPLUNK_HOME", "/opt/splunk")
sys.path.append(os.path.join(_SPLUNK_HOME, "etc", "apps", "Splunk_SA_CIM", "bin"))
try:
    from cim_actions import ModularAction
except ImportError:
    ModularAction = None


# ----------------------------------------------------------------------
# Logging - writes to $SPLUNK_HOME/var/log/splunk/notable_to_slack_json.log
# ----------------------------------------------------------------------
def setup_logging():
    log_dir = os.path.join(os.environ.get("SPLUNK_HOME", "/opt/splunk"), "var", "log", "splunk")
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
# Token substitution for the additional_fields template
# ----------------------------------------------------------------------
def substitute_tokens(template, row, job):
    def repl(m):
        scope, field = m.group(1), m.group(2)
        source = row if scope == "result" else job
        return str(source.get(field, ""))

    return TOKEN_RE.sub(repl, template)


# ----------------------------------------------------------------------
# Pull the triggering event row(s) out of the Splunk-provided payload
# ----------------------------------------------------------------------
def load_rows(payload):
    if payload.get("result"):
        return [payload["result"]]

    rows = []
    results_file = payload.get("results_file")
    if results_file and os.path.exists(results_file):
        opener = gzip.open if results_file.endswith(".gz") else open
        with opener(results_file, "rt", encoding="utf-8", errors="replace") as fh:
            reader = csv.DictReader(fh)
            for row in reader:
                rows.append(row)
    return rows


# ----------------------------------------------------------------------
# Build the outgoing JSON envelope
# ----------------------------------------------------------------------
def build_payload(row, job, cfg):
    denylist = {f.strip() for f in cfg.get("field_denylist", "").split(",") if f.strip()}
    include_raw = cfg.get("include_raw_event", "0") in ("1", "true", "True")
    if not include_raw:
        denylist.add("_raw")

    notable_fields = {k: v for k, v in row.items() if k not in denylist}

    additional = {}
    raw_additional = (cfg.get("additional_fields") or "").strip()
    if raw_additional:
        substituted = substitute_tokens(raw_additional, row, job)
        try:
            additional = json.loads(substituted)
        except json.JSONDecodeError as e:
            log.warning("additional_fields is not valid JSON after token substitution: %s", e)
            additional = {"_additional_fields_raw": substituted, "_parse_error": str(e)}

    return {
        "source": "splunk_es_adaptive_response",
        "action": APP_NAME,
        "sent_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "search_name": job.get("search_name"),
        "sid": job.get("sid"),
        "app": job.get("app"),
        "owner": job.get("owner"),
        "results_link": job.get("results_link"),
        "server_host": job.get("server_host"),
        "notable": notable_fields,
        "additional_fields": additional,
    }


# ----------------------------------------------------------------------
# Slack credential vault lookup (recommended over plaintext token param)
# ----------------------------------------------------------------------
def get_secret_from_vault(server_uri, session_key, realm, app):
    """Fetch a clear-text password from Splunk's storage/passwords vault by realm.
    Uses an unverified TLS context because this call targets splunkd's own
    management port (typically self-signed / internally issued cert)."""
    url = (
        f"{server_uri}/servicesNS/nobody/{app}/storage/passwords"
        f"?output_mode=json&count=0&search=realm%3D{urllib.parse.quote(realm)}"
    )
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"Authorization": f"Splunk {session_key}"})
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        data = json.loads(resp.read().decode("utf-8"))
    for entry in data.get("entry", []):
        content = entry.get("content", {})
        if content.get("realm") == realm:
            return content.get("clear_password")
    return None


# ----------------------------------------------------------------------
# Write the collected Slack data back onto the SAME notable so it shows
# up in the analyst's queue as part of that notable's own Activity trail
# (not just a status flag). Only comment/status/urgency/newOwner/
# disposition are writable via this endpoint - no arbitrary new fields.
# https://help.splunk.com/en/splunk-enterprise-security-7/api-reference/7.2/notable-event-endpoints/notable-event-api-reference
# ----------------------------------------------------------------------
def post_comment_to_notable(server_uri, session_key, event_id, comment):
    if not server_uri or not session_key:
        raise RuntimeError("server_uri/session_key unavailable; cannot call notable_update")
    url = f"{server_uri}/services/notable_update"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = urllib.parse.urlencode({"ruleUIDs": event_id, "comment": comment}).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST", headers={"Authorization": f"Splunk {session_key}"}
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    log.info("Wrote comment back to notable event_id=%s: %s", event_id, result)
    return result


# ----------------------------------------------------------------------
# Write a STRUCTURED enrichment record to the notable_slack_enrichment KV
# store collection, keyed by this AR invocation's sid/rid (the only tokens
# Incident Review's custom drilldown_uri supports - event_id is NOT one of
# them). Analysts reach this via the drilldown configured in param._cam,
# rendered by default/data/ui/views/notable_slack_enrichment_drilldown.xml.
# https://dev.splunk.com/view/SP-CAAAEZG (KV store REST write)
# ----------------------------------------------------------------------
def write_kvstore_record(server_uri, session_key, app, record):
    if not server_uri or not session_key:
        raise RuntimeError("server_uri/session_key unavailable; cannot write to KV store")
    url = f"{server_uri}/servicesNS/nobody/{app}/storage/collections/data/notable_slack_enrichment"
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    body = json.dumps(record).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={"Authorization": f"Splunk {session_key}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    log.info("Wrote KV store enrichment record _key=%s", result.get("_key"))
    return result


# ----------------------------------------------------------------------
# Human-readable timestamp for when the underlying event/notable actually
# occurred, as opposed to envelope['sent_at'] (when this action ran).
# Splunk notable rows carry the event time in _time (epoch seconds); fall
# back to the row's own 'time' field, then to sent_at if neither is present.
# ----------------------------------------------------------------------
def format_event_time(row, envelope):
    raw_time = row.get("_time") or row.get("time")
    if raw_time:
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S %Z", time.localtime(float(raw_time)))
        except (TypeError, ValueError):
            return str(raw_time)
    return envelope.get("sent_at", "")


# ----------------------------------------------------------------------
# Slack delivery: file_upload (recommended - no size limit)
# ----------------------------------------------------------------------
def slack_api_post(url, token, data=None, json_body=None):
    headers = {"Authorization": f"Bearer {token}"}
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers["Content-Type"] = "application/json; charset=utf-8"
    else:
        body = urllib.parse.urlencode(data).encode("utf-8")
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    req = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read().decode("utf-8"))


def upload_json_to_slack(token, channel, filename, json_bytes, comment):
    # Step 1: request an upload URL (files.upload is retired as of 2025-11-12)
    step1 = slack_api_post(
        "https://slack.com/api/files.getUploadURLExternal",
        token,
        data={"filename": filename, "length": str(len(json_bytes))},
    )
    if not step1.get("ok"):
        raise RuntimeError(f"files.getUploadURLExternal failed: {step1}")
    upload_url, file_id = step1["upload_url"], step1["file_id"]

    # Step 2: POST the raw JSON bytes to that URL
    req = urllib.request.Request(
        upload_url, data=json_bytes, method="POST",
        headers={"Content-Type": "application/octet-stream"},
    )
    with urllib.request.urlopen(req, timeout=60) as resp:
        resp.read()

    # Step 3: finalize + share into the channel
    step3 = slack_api_post(
        "https://slack.com/api/files.completeUploadExternal",
        token,
        json_body={
            "files": [{"id": file_id, "title": filename}],
            "channel_id": channel,
            "initial_comment": comment,
        },
    )
    if not step3.get("ok"):
        raise RuntimeError(f"files.completeUploadExternal failed: {step3}")
    return step3


# ----------------------------------------------------------------------
# Slack delivery: webhook (quick start, truncates large payloads)
# ----------------------------------------------------------------------
def post_webhook_summary(webhook_url, envelope, row, max_chars=3500):
    text_json = json.dumps(envelope, indent=2, default=str)
    truncated = len(text_json) > max_chars
    snippet = text_json[:max_chars]
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": (
                    f"*Notable - {envelope.get('search_name', '')}*\n"
                    f"Event time: {format_event_time(row, envelope)}"
                ),
            },
        },
        {"type": "section", "text": {"type": "mrkdwn", "text": f"```{snippet}```"}},
    ]
    if truncated:
        blocks.append(
            {
                "type": "context",
                "elements": [
                    {
                        "type": "mrkdwn",
                        "text": ":warning: JSON truncated to fit Slack limits. "
                        "Switch delivery_method to file_upload for the full payload.",
                    }
                ],
            }
        )
    body = json.dumps({"blocks": blocks}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url, data=body, method="POST", headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("FATAL usage: notable_to_slack_json.py --execute\n")
        sys.exit(1)

    try:
        raw_stdin = sys.stdin.read()
        payload = json.loads(raw_stdin)
    except Exception:
        log.exception("Failed to parse payload JSON from stdin")
        sys.exit(2)

    # cim_actions.ModularAction wraps the SAME stdin payload and gives us
    # self.message() -> Incident Review's native "Adaptive Responses" panel.
    # It also deletes payload['result'] internally, so it must be built from
    # the raw JSON string, not the already-parsed `payload` dict.
    modaction = None
    if ModularAction is not None:
        try:
            modaction = ModularAction(raw_stdin, log, APP_NAME)
        except Exception:
            log.exception(
                "Failed to initialize cim_actions.ModularAction; continuing "
                "without native Adaptive Response panel reporting"
            )

    cfg = payload.get("configuration", {}) or {}
    write_back_comment = (cfg.get("write_back_comment", "1")) in ("1", "true", "True")
    write_back_kvstore = (cfg.get("write_back_kvstore", "1")) in ("1", "true", "True")
    kvstore_app = payload.get("app", "TA_ResponseActions") or "TA_ResponseActions"
    job = {
        "search_name": payload.get("search_name"),
        "sid": payload.get("sid"),
        "app": payload.get("app"),
        "owner": payload.get("owner"),
        "results_link": payload.get("results_link"),
        "server_host": payload.get("server_host"),
    }

    rows = load_rows(payload)
    if not rows:
        log.warning("No result rows found in payload for sid=%s", job.get("sid"))
        sys.exit(0)

    try:
        max_events = int(cfg.get("max_events") or 5)
    except ValueError:
        max_events = 5

    delivery = (cfg.get("delivery_method") or "file_upload").strip()
    pretty = (cfg.get("pretty_print", "1")) in ("1", "true", "True")

    # Resolve the Slack bot token: prefer the credential vault realm.
    token = (cfg.get("slack_bot_token") or "").strip()
    realm = (cfg.get("slack_bot_token_realm") or "").strip()
    if delivery == "file_upload" and not token and realm:
        try:
            token = get_secret_from_vault(
                payload.get("server_uri"), payload.get("session_key"), realm, payload.get("app", "search")
            )
        except Exception:
            log.exception("Failed to fetch Slack bot token from vault realm=%s", realm)

    failures = 0
    for i, row in enumerate(rows[:max_events]):
        envelope = build_payload(row, job, cfg)
        json_bytes = json.dumps(envelope, indent=2 if pretty else None, default=str).encode("utf-8")

        # update() sets rid/orig_sid/orig_rid so message() correlates the
        # status back to THIS specific notable row in the AR audit trail.
        if modaction is not None:
            try:
                modaction.update(
                    {
                        "rid": row.get("rid", str(i)),
                        "orig_sid": row.get("orig_sid", ""),
                        "orig_rid": row.get("orig_rid", ""),
                    }
                )
            except Exception:
                log.exception("modaction.update() failed for row=%d", i)

        try:
            if delivery == "webhook":
                webhook_url = cfg.get("slack_webhook_url")
                if not webhook_url:
                    raise RuntimeError("slack_webhook_url is not configured")
                post_webhook_summary(webhook_url, envelope, row)
            else:
                channel = cfg.get("slack_channel")
                if not token or not channel:
                    raise RuntimeError(
                        "slack_bot_token (or slack_bot_token_realm) and slack_channel are required "
                        "for file_upload delivery"
                    )
                filename = f"notable_{job.get('sid', 'na')}_{i}.json"
                comment = (
                    f"Notable - {job.get('search_name')}\n"
                    f"Event time: {format_event_time(row, envelope)}"
                )
                upload_json_to_slack(token, channel, filename, json_bytes, comment)
            log.info("Delivered notable sid=%s row=%d to Slack via %s", job.get("sid"), i, delivery)

            # 1) Native Adaptive Response panel status for this notable.
            if modaction is not None:
                try:
                    modaction.message(
                        f"Sent notable to Slack via {delivery}",
                        status="success",
                        channel=cfg.get("slack_channel") or "",
                    )
                except Exception:
                    log.exception("modaction.message() (success) failed for row=%d", i)

            # 2) Persisted comment on the SAME notable's own Activity trail,
            #    so the collected/sent data is visible with the rest of the
            #    notable in the analyst's Incident Review queue.
            if write_back_comment:
                event_id = row.get("event_id")
                if event_id:
                    try:
                        post_comment_to_notable(
                            payload.get("server_uri"),
                            payload.get("session_key"),
                            event_id,
                            f"Sent to Slack via {delivery} at {envelope['sent_at']}.\n"
                            f"Additional fields: "
                            f"{json.dumps(envelope.get('additional_fields'), default=str)}",
                        )
                    except Exception:
                        log.exception(
                            "Failed to write comment back to notable event_id=%s", event_id
                        )
                else:
                    log.debug(
                        "No event_id on row=%d (not a notable-context invocation); "
                        "skipping notable comment write-back",
                        i,
                    )

            # 3) Structured enrichment record in the KV store, keyed by
            #    sid/rid so it can be reached via the drilldown_uri custom
            #    view - gives analysts real fields, not just comment text.
            if write_back_kvstore:
                try:
                    write_kvstore_record(
                        payload.get("server_uri"),
                        payload.get("session_key"),
                        kvstore_app,
                        {
                            "sid": job.get("sid") or "",
                            "rid": row.get("rid", str(i)),
                            "orig_sid": row.get("orig_sid", ""),
                            "orig_rid": row.get("orig_rid", ""),
                            "event_id": row.get("event_id", ""),
                            "sent_at": envelope["sent_at"],
                            "delivery_method": delivery,
                            "slack_channel": cfg.get("slack_channel") or "",
                            "slack_permalink": "",
                            "additional_fields": json.dumps(
                                envelope.get("additional_fields"), default=str
                            ),
                            "status": "success",
                            "error": "",
                        },
                    )
                except Exception:
                    log.exception(
                        "Failed to write KV store enrichment record for row=%d", i
                    )
        except Exception:
            log.exception("Failed to deliver notable sid=%s row=%d to Slack", job.get("sid"), i)
            failures += 1
            if modaction is not None:
                try:
                    modaction.message(
                        f"Failed to deliver notable to Slack via {delivery}",
                        status="failure",
                        level=logging.ERROR,
                    )
                except Exception:
                    log.exception("modaction.message() (failure) failed for row=%d", i)
            if write_back_kvstore:
                try:
                    write_kvstore_record(
                        payload.get("server_uri"),
                        payload.get("session_key"),
                        kvstore_app,
                        {
                            "sid": job.get("sid") or "",
                            "rid": row.get("rid", str(i)),
                            "orig_sid": row.get("orig_sid", ""),
                            "orig_rid": row.get("orig_rid", ""),
                            "event_id": row.get("event_id", ""),
                            "sent_at": envelope.get("sent_at", ""),
                            "delivery_method": delivery,
                            "slack_channel": cfg.get("slack_channel") or "",
                            "slack_permalink": "",
                            "additional_fields": json.dumps(
                                envelope.get("additional_fields"), default=str
                            ),
                            "status": "failure",
                            "error": str(sys.exc_info()[1]),
                        },
                    )
                except Exception:
                    log.exception(
                        "Failed to write KV store failure record for row=%d", i
                    )

    sys.exit(0 if failures == 0 else 3)


if __name__ == "__main__":
    main()

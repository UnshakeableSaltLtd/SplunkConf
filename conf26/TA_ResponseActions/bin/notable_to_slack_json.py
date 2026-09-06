#!/usr/bin/env python3
"""
notable_to_slack_json.py
--------------------------------------------------------------------
Splunk Enterprise Security custom Adaptive Response Action.

NOTIFICATION FLOW ONLY - this action is NOT part of the agentic
response process (see notable_to_perplexity_json.py for that). It
posts the triggering Notable/Finding to the #es-findings Slack channel
as a complete JSON payload - built via ta_common.build_payload(), the
EXACT same envelope shape sent as context to the Perplexity API by
notable_to_perplexity_json.py. This action never calls Perplexity and
never merges a "perplexity_response" object in: if additional_fields
carries a "perplexity_ask" block, it is posted to Slack unanswered,
purely for visual/human audit of what the agentic action was asked to
evaluate.

The two actions were split in v1.4.0 so the agentic loop (Perplexity)
and the human notification channel (Slack) can be enabled, disabled,
or have their credentials rotated completely independently - see
README.md's 1.4.0 release notes.

After delivery, the action writes back to the SAME notable so
analysts see the result alongside the rest of the event in Incident
Review:
  1. cim_actions.ModularAction.message() -> native "Adaptive Responses"
     panel / "View Adaptive Response Invocations" audit trail.
  2. /services/notable_update comment -> a permanent entry in that
     notable's own Activity/comment timeline.
  3. notable_agentic_enrichment KV store record -> structured fields
     (same additional_fields JSON) surfaced via a custom drilldown -
     the SAME collection/drilldown notable_to_perplexity_json.py also
     writes to.

Install at:
  $SPLUNK_HOME/etc/apps/TA_ResponseActions/bin/notable_to_slack_json.py

Contract: Splunk invokes this script as:
  notable_to_slack_json.py --execute
and writes the alert configuration payload (JSON) to stdin.
See: https://dev.splunk.com/enterprise/docs/devtools/customalertactions/writescriptcaa
--------------------------------------------------------------------
"""
import json
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ta_common  # noqa: E402

APP_NAME = "notable_to_slack_json"
log = ta_common.setup_logging(APP_NAME)


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        # This is the ONLY place this script exits 1 - see the matching
        # comment in notable_to_perplexity_json.py. Log full invocation
        # context unconditionally so a Splunk-side invocation mismatch is
        # diagnosable from the log file alone (added in 1.4.4).
        try:
            log.error(
                "FATAL invocation contract violation: expected argv[1]=='--execute', "
                "got argv=%r | python=%s | executable=%s | cwd=%s | script=%s",
                sys.argv, sys.version.replace("\n", " "), sys.executable,
                os.getcwd(), os.path.abspath(__file__),
            )
        except Exception:
            pass
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
    if ta_common.ModularAction is not None:
        try:
            modaction = ta_common.ModularAction(raw_stdin, log, APP_NAME)
        except Exception:
            log.exception(
                "Failed to initialize cim_actions.ModularAction; continuing "
                "without native Adaptive Response panel reporting"
            )

    cfg = payload.get("configuration", {}) or {}
    write_back_comment = (cfg.get("write_back_comment", "1")) in ("1", "true", "True")
    write_back_kvstore = (cfg.get("write_back_kvstore", "1")) in ("1", "true", "True")
    test_connectivity = (cfg.get("test_connectivity", "0")) in ("1", "true", "True")
    kvstore_app = payload.get("app", "TA_ResponseActions") or "TA_ResponseActions"

    # Unconditional heartbeat: every single invocation of this script leaves
    # this log line no matter what happens next (bad payload, no rows, an
    # unhandled exception, a crash) - so "did the alert action even run" is
    # never a question that needs guessing at from an empty/missing log file.
    log.info(
        "Invoked: sid=%s search_name=%s test_connectivity=%s delivery_method=%s",
        payload.get("sid"), payload.get("search_name"), test_connectivity,
        cfg.get("delivery_method") or "file_upload",
    )

    if test_connectivity:
        # Side-effect-free credential check: no rows are loaded, nothing is
        # sent to Slack, nothing is written back to any notable or KV store.
        # Slack-only, since this action has no Perplexity credential to test
        # (see notable_to_perplexity_json.py for the Perplexity-side test).
        slack_ok, slack_detail = ta_common.check_slack_connectivity(
            cfg, payload.get("server_uri"), payload.get("session_key"),
            payload.get("app", "search"), log,
        )
        overall_ok = slack_ok is not False
        log.info(
            "test_connectivity summary: slack_ok=%s (%s) -> %s",
            slack_ok, slack_detail, "PASS" if overall_ok else "FAIL",
        )
        if modaction is not None:
            try:
                modaction.message(
                    f"test_connectivity: slack_ok={slack_ok}",
                    status="success" if overall_ok else "failure",
                    level=logging.INFO if overall_ok else logging.ERROR,
                )
            except Exception:
                log.exception("modaction.message() failed for test_connectivity summary")
        sys.exit(0 if overall_ok else 3)

    job = {
        "search_name": payload.get("search_name"),
        "sid": payload.get("sid"),
        "app": payload.get("app"),
        "owner": payload.get("owner"),
        "results_link": payload.get("results_link"),
        "server_host": payload.get("server_host"),
    }

    rows = ta_common.load_rows(payload)
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
    token, token_source = ("", "not needed (delivery_method=webhook)")
    if delivery != "webhook":
        token, token_source = ta_common.resolve_slack_bot_token(
            cfg, payload.get("server_uri"), payload.get("session_key"),
            payload.get("app", "search"), log,
        )
        log.info("Slack bot token resolved from: %s", token_source)

    failures = 0
    for i, row in enumerate(rows[:max_events]):
        # Same envelope shape sent to the Perplexity API by
        # notable_to_perplexity_json.py - built via the shared
        # ta_common.build_payload(). Any "perplexity_ask" block in
        # additional_fields is posted as-is, unanswered - this action
        # never calls Perplexity.
        envelope = ta_common.build_payload(row, job, cfg, log, APP_NAME)
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

        slack_permalink = ""

        try:
            if delivery == "webhook":
                webhook_url = cfg.get("slack_webhook_url")
                if not webhook_url:
                    raise RuntimeError("slack_webhook_url is not configured")
                ta_common.post_webhook_summary(webhook_url, envelope, row)
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
                    f"Event time: {ta_common.format_event_time(row, envelope)}"
                )
                upload_resp = ta_common.upload_json_to_slack(
                    token, channel, filename, json_bytes, comment
                )
                uploaded_files = upload_resp.get("files") or []
                if uploaded_files:
                    slack_permalink = uploaded_files[0].get("permalink", "") or ""
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
                        ta_common.post_comment_to_notable(
                            payload.get("server_uri"),
                            payload.get("session_key"),
                            event_id,
                            f"Sent to Slack via {delivery} at {envelope['sent_at']}.\n"
                            f"Additional fields: "
                            f"{json.dumps(envelope.get('additional_fields'), default=str)}",
                            log,
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

            # 3) Structured enrichment record in the SAME KV store collection
            #    notable_to_perplexity_json.py also writes to, keyed by
            #    sid/rid so it can be reached via the drilldown_uri custom
            #    view - gives analysts real fields, not just comment text.
            if write_back_kvstore:
                try:
                    ta_common.write_kvstore_record(
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
                            "slack_permalink": slack_permalink,
                            "additional_fields": json.dumps(
                                envelope.get("additional_fields"), default=str
                            ),
                            "status": "success",
                            "error": "",
                        },
                        log,
                    )
                except Exception:
                    log.exception(
                        "Failed to write KV store enrichment record for row=%d", i
                    )
        except (ta_common.SlackApiError, Exception) as e:
            if isinstance(e, ta_common.SlackApiError) and e.is_auth_error:
                log.error(
                    "SLACK AUTH FAILURE: %s failed with error=%s (token source=%s) while "
                    "delivering notable sid=%s row=%d - credential is invalid/expired/revoked, "
                    "not a transient error",
                    e.method, e.error, token_source, job.get("sid"), i,
                )
            else:
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
                    ta_common.write_kvstore_record(
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
                            "slack_permalink": slack_permalink,
                            "additional_fields": json.dumps(
                                envelope.get("additional_fields"), default=str
                            ),
                            "status": "failure",
                            "error": str(sys.exc_info()[1]),
                        },
                        log,
                    )
                except Exception:
                    log.exception(
                        "Failed to write KV store failure record for row=%d", i
                    )

    sys.exit(0 if failures == 0 else 3)


if __name__ == "__main__":
    main()

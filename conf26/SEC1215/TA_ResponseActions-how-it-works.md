# How TA_ResponseActions Closes the Agentic Investigation Loop in Splunk ES

`TA_ResponseActions` is the working implementation behind the agentic investigation pattern demonstrated in **SEC1215, _From Zero to Agentic: Building Your First AI-Driven Threat Investigation in Splunk Enterprise Security_**. It is a custom Splunk Enterprise Security Adaptive Response Action that takes a notable event, gives an AI service the complete context and a consistent set of questions, and records the result where analysts already work.

The aim is deliberately practical: connect an AI decision to Splunk ES workflow without requiring an analyst to copy, paste, or chase an answer in another system. The loop is:

> **Detect → decide → act → record**

A correlation search detects the finding; `TA_ResponseActions` prepares the evidence and asks the model to assess it; the action delivers the result to Slack, the notable timeline, and a KV Store-backed drilldown. The implementation discussed in SEC1215 is synchronous: the AI response is returned while the Adaptive Response Action is running, rather than being collected by a separate poller later.

This article focuses on how that shipped app works. For the talk narrative, architecture decisions, and the lessons behind the design, see the [SEC1215 materials](README.md).

## Why TA_ResponseActions exists

An LLM response is not, by itself, an Enterprise Security workflow. A useful security investigation needs several things to happen reliably:

- The model needs enough evidence to reason over the actual finding, rather than a lossy hand-written summary.
- The investigation needs a repeatable set of questions, so the response is relevant to the detection and comparable across notables.
- The outcome needs to return to the analyst in the systems they already use.
- The action needs to be observable and operationally safe when an external API is slow or unavailable.

Splunk ES already provides the trigger and much of the surrounding workflow: correlation searches raise notables, the Adaptive Response framework runs a custom action, the Adaptive Responses panel reports its status, the Notable Event API can write a timeline comment, and KV Store can retain structured enrichment for a drilldown. `TA_ResponseActions` supplies the glue between those platform primitives and an AI investigation call.

The app is not intended to replace analyst judgement or to silently mutate the original notable with arbitrary new fields. Instead, it creates an auditable investigation record: what was sent, what was asked, what the model returned, and where an analyst can inspect it.

## How the action works

### 1. A notable triggers the Adaptive Response Action

A Splunk ES correlation search creates a notable event and invokes the custom `notable_to_perplexity_json` action supplied by `TA_ResponseActions`. The action is implemented as a Splunk `ModularAction`, which means it participates in the native Adaptive Responses experience rather than requiring a separate control plane or custom analyst UI.

The action receives the triggering result and the alert-action configuration. It also keeps the correlation information needed to associate downstream records with the originating notable, including the search and event identifiers available to the action.

### 2. The action builds an investigation envelope

The action serialises the available notable, CIM, and risk context into a JSON envelope. This is intentionally a **full-context** design: the model receives the useful event context an analyst would expect to inspect, rather than an aggressively size-limited prompt summary.

Before delivery, configured noise fields are removed through a denylist. The point is not to hide the evidence; it is to avoid sending fields that add no investigative value or create unnecessary payload noise.

The envelope contains both the notable context and a `perplexity_ask` block. That block holds the standing investigation questions configured for the action. A typical deployment uses questions such as:

- Is the repository commonly associated with this type of finding?
- Is the user expected or authorised in this context?
- Does the source IP appear low threat?

These questions can use result-field substitutions, allowing each correlation search to pass the relevant repository, identity, IP address, or other evidence into the same reusable investigation pattern.

### 3. The model is called synchronously with a schema

The action calls the Perplexity Chat Completions API in-line. The selected model is configuration-driven, so changing model choice does not require rewriting the integration.

Crucially, the request uses the API's structured-output capability: the action provides a JSON Schema through `response_format` and receives a `perplexity_response` object that matches the expected response shape. This avoids treating a free-text answer as an API contract and then trying to scrape JSON out of prose.

The synchronous call makes latency an explicit part of the alert-action budget, but it also removes an entire asynchronous hand-off. There is no need for a second component to poll a Slack thread, retrieve a reply, parse it, and decide whether it is valid. The response is available before the action writes its final results.

### 4. One payload is written back through three paths

Once the action has the AI response, it carries the ask-and-response pair through three existing paths:

| Destination | What it provides |
| --- | --- |
| **Slack** | A per-notable delivery that makes the payload and returned assessment visible as the investigation happens. |
| **Notable Event API** | A concise comment on the originating notable, visible in the Activity timeline in Incident Review. The comment records what was sent and includes the returned assessment. |
| **KV Store and drilldown** | A structured record in the `notable_slack_enrichment` collection containing the full investigation envelope, including `perplexity_ask` and `perplexity_response`. Analysts can open it from the notable's Adaptive Responses panel. |

Slack delivery supports two modes:

- **`file_upload`** uses a Slack bot token and uploads the JSON as a file. This is the preferred option for complete payloads because it avoids webhook message-size truncation.
- **`webhook`** is a quick-start option using an incoming webhook. It is useful for simple deployments, but large JSON payloads can be truncated.

The important architectural distinction is that Slack is a delivery and audit surface, not a dependency for receiving the AI answer. The model response has already been returned in the action process before the Slack write-back occurs.

### 5. Analysts investigate from Splunk ES

The action uses Splunk's native Adaptive Response reporting so its status is visible on the originating notable. Analysts can use that panel to open the drilldown and inspect the full stored record, while the notable's Activity timeline provides an immediately visible summary. Slack offers an additional real-time view for teams that use it during triage.

This makes the result traceable: an analyst can compare the original evidence, the standing questions, and the AI response rather than receiving an unexplained verdict.

## Configuration and operating model

The reusable pattern is configured per correlation search rather than rebuilt per use case. In practice, deployment consists of:

1. Installing `TA_ResponseActions` and configuring its credentials and endpoints.
2. Selecting the delivery mode and, for file upload, supplying a Slack bot token.
3. Choosing the configured Perplexity model and API credential.
4. Adding the `notable_to_perplexity_json` Adaptive Response Action to a correlation search.
5. Defining the `perplexity_ask` questions and any field substitutions appropriate to that detection.

This separation matters. The integration code remains consistent, while the questions and event fields can change with the detection. Teams can begin with a small number of high-value standing checks, observe quality and latency, and adjust the model or questions as they would tune a detection.

## Design boundaries

`TA_ResponseActions` deliberately uses Splunk-native paths where they fit and makes its limitations visible where they do not. In particular, the Notable Event API can add a comment and update supported notable attributes, but it does not add arbitrary structured fields to the existing indexed notable. That is why the full enrichment is retained in KV Store and exposed through a drilldown, rather than being presented as if it were a permanent field added to the original notable.

The current synchronous design also does **not** write the AI result to the Risk Index as a CIM risk modifier. An earlier asynchronous bridge pattern explored that route; the implementation shown in SEC1215 prioritises a simpler in-process loop and analyst-visible record through Slack, the notable timeline, and KV Store. The retired implementation's design and the pitfalls it surfaced remain documented in this repository's [`ARCHITECTURE.md`](./ARCHITECTURE.md) as a learning resource; the retired code itself is not included in this public repository.

## Relationship to SEC1215

SEC1215 uses this app as a concrete, open-source example of building an agentic workflow in Splunk ES. The talk's three themes are visible in the implementation:

- **Choose the model for the operating context.** Cost, latency, privacy, and capability matter more than selecting the largest model by default.
- **Build the minimum glue.** Adaptive Response Actions, the Notable Event API, KV Store, and Splunk ES analyst workflows provide much of the foundation; the app focuses on payload shaping, standing questions, and the structured AI call.
- **Treat simplification as a result.** The current design removed a separate Slack-to-HEC polling bridge after proving that the response could be obtained synchronously and written back through the paths already in use.

The result is not a generic claim of autonomous security operations. It is a specific, inspectable loop that teams can adapt: a detection produces evidence, an AI service assesses it against known questions, and the response returns to the workflow that generated the finding.

## Thank you

Thank you to everyone who attended SEC1215 and took the time to explore the code, questions, and trade-offs behind this implementation. We hope the app and the accompanying materials make it easier to start with one useful investigation loop, learn from it, and build from there.

**Talk recording:** _[Link to the SEC1215 session recording will be added here when it is published.]_

For the source, installation guidance, architecture notes, and retired-design lessons, visit the [SEC1215 directory](README.md) and the [`TA_ResponseActions` app](../../apps/TA_ResponseActions/README.md).

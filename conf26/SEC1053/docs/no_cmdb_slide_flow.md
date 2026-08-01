# SEC1053 — Core Section Discussion Flow: Tackling Assets & Identity Without a CMDB

**Status:** Planning outline only — no slide visuals created yet. This is the discussion flow for the ~10-minute core section of the talk, sitting between the intro slides and the takeaways wrap-up.

**Session:** SEC1053 — "The other AI: Assets and Identity. Using Splunk to keep in check"
**Format:** Theater Session, 20 minutes total (Wed Sep 16, 3:00–3:20 PM MDT)
**Maps to takeaways** (see `SEC1053.md`):
- T1 — Continuous asset discovery and risk tracking
- T2 — Automated governance workflows for CAF / NIST CSF compliance
- T3 — Turning compliance reports into proactive, automated security actions

> **Cross-session note (idea, not yet committed to a slide):** SEC1215 ("From Zero to Agentic: Building Your First AI-Driven Threat Investigation in Splunk Enterprise Security," Tue Sep 15) builds an agentic AI loop where ES notable/CIM data is sent to an LLM (via `perplexity_ask` inside an alert action) which returns a structured, schema-shaped answer written straight back into Slack, the notable's comment trail, and a KV Store enrichment record — see [`conf26/SEC1215/ARCHITECTURE.md`](https://github.com/UnshakeableSaltLtd/SplunkConf/blob/main/conf26/SEC1215/ARCHITECTURE.md). That's a strong candidate use case for Slide 6 below: when Splunk surfaces an asset it can't classify (unknown device on the network, unrecognized cloud instance, orphaned identity), the same agentic pattern could reason over the raw signal and propose a classification/owner back into the asset KV Store — turning "data you don't have" into a self-healing gap rather than a permanent blind spot. Worth a callback line or a "see also SEC1215" pointer if both talks run at the same conference and audience overlap is likely.

---

## Slide 1 — Defining Terms: What Is an Asset? What Is an Identity?

Ground the audience before diving into the problem — "assets and identity" gets thrown around loosely, and the talk depends on a shared definition.

- **Asset:** any component of the technical estate that must be identified, tracked, and secured — physical hardware, VMs, cloud instances, containers, code repositories, SaaS/third-party services. Not just servers and laptops.
- **Identity:** any entity — human or non-human — that authenticates and is granted access: users, service accounts, API keys, workload identities, certificates.
- **The key relationship:** assets and identities are two axes of the same risk. An asset is compromised *through* an identity; an identity's blast radius is defined by *which assets it can reach*. You can't reason about risk with only one half of the picture.
- Anchor this to the frameworks early: NIST CSF's ID.AM category already spans both physical/software assets *and* personnel, and CAF Principle A3 (Asset Management) expects you to know what you have before you can protect it.

## Slide 2 — The Reality Check

"Most orgs don't have a CMDB. The ones that do don't trust it."
Set the stakes: without asset visibility, ES notable events have no risk context, no ownership, no priority — every alert is just noise with a hostname attached.

## Slide 3 — Why CMDBs Fail (Even When They Exist)

Manual entry drift, M&A sprawl, shadow IT, ephemeral cloud instances, ownership silos. The CMDB is a snapshot; your environment is a stream.

## Slide 4 — Reframe: ES Isn't a CMDB Replacement, It's an Enrichment Layer

Correct the common misconception. Splunk ES's asset framework was built to consume identity data, not generate it from nothing. This sets up the hybrid pattern: if a CMDB exists, keep it as one input — not the only one.

## Slide 5 — The Data You Already Have

You don't need a new tool — you need to trust your existing telemetry: DHCP leases, VPN/NAC logs, EDR/endpoint check-ins, cloud provider metadata (AWS/Azure/GCP tags), DNS, AD/Entra ID. Every one of these already proves an asset is alive, right now — fresher than any CMDB export.

## Slide 6 — The Data You Don't Have (And Why That's Why Enterprise Security Fails)

The honest counterpart to Slide 5. Even with DHCP, VPN, EDR, and cloud metadata feeding in, there are always gaps — and those gaps are where breaches actually happen.

- **Classic blind spots:** unmanaged BYOD, shadow IT/SaaS nobody provisioned through IT, decommissioned-but-still-live cloud resources nobody tore down, OT/IoT devices with no agent capability, contractor/third-party laptops, orphaned service accounts, undocumented API integrations, pre-EDR-rollout assets, and M&A-inherited environments never fully onboarded.
- **The core point:** an unmonitored asset isn't a "known unknown" on a risk register — it's genuinely invisible. Your SIEM, EDR, and vulnerability scanner are only as good as their coverage; nothing analyzes telemetry that was never generated.
- **Reframe the failure mode:** security incidents are rarely "the SOC missed the alert." They're far more often "there was no telemetry source there at all" — the forgotten storage bucket, the still-routable decommissioned VPN concentrator, the admin account nobody remembered existed.
- **Bridge to Takeaway 1:** this is exactly why *continuous* discovery matters more than a one-off inventory project — the goal isn't to close the gap once, it's to keep noticing when something new and unmonitored appears.
- **Possible callback (see cross-session note above):** when Splunk detects something and genuinely can't classify it, that's a candidate use case for the agentic AI pattern from SEC1215 — an LLM reasoning over the raw signal to propose what it might be and writing that back into the asset/identity KV Store, rather than the gap just sitting there until a human investigates.

## Slide 7 — The Hard Part: Identity Correlation, Not Collection

The real challenge with the data you *do* have isn't gathering it, it's correlating hostname/IP/MAC/cloud-instance-ID into one canonical asset identity over time — through DHCP churn, VPN NAT, ephemeral instances. Introduce the need for a normalization schema here.

## Slide 8 — Building the "Poor Man's CMDB" in Splunk

Scheduled searches normalize and push identity data into KV Store lookups — continuously refreshed, always current. Reference Asset and Risk Intelligence (ARI) as Splunk's productized version of this exact pattern.

## Slide 9 — Architecture Walkthrough

Data flow diagram: sources → normalization searches → KV Store lookup → ES Asset framework → enriched notable events. Show the actual lookup schemas here — `asset_lookup_schema.json` / `identity_lookup_schema.json` and the ES 8.5.1 YAML templates already in `conf26/SEC1053/Proof_of_concept/`.

## Slide 10 — Bridge to Takeaway 2: Governance Gets Measurable

Once you have continuous coverage, map it directly to CAF Principle A3 (Asset Management) and NIST CSF ID.AM. Completeness, freshness, and ownership become auditable KPIs instead of a point-in-time spreadsheet an auditor has to take on faith.

## Slide 11 — Bridge to Takeaway 3: From Visibility to Automated Action

Tagged, risk-scored assets let you automate: rogue-asset detection when something unmanaged appears on the network, automatic ticket creation, dynamic risk re-scoring. The compliance report stops being a PDF and becomes a live trigger.

## Slide 12 — Recap & Handoff

"You don't need a CMDB — you need continuous, correlated identity." One-line summary that hands cleanly into the wrap-up slides tying back to all three official takeaways.

---

**Notes:**
- This arc builds toward all three takeaways in sequence: T1 → slides 2–9, T2 → slide 10, T3 → slide 11.
- Supporting artifacts already in the repo that slide 9 should reference: `Proof_of_concept/Splunk ES 8.5.1 Asset Lookup — YAML Template.yml`, `Proof_of_concept/Splunk ES 8.5.1 Identity Lookup — YAML Template.yml`, and the project's `asset_lookup_schema.json` / `identity_lookup_schema.json`.

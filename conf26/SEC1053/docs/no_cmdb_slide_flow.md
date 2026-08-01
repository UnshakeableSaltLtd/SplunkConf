# SEC1053 — Core Section Discussion Flow: Tackling Assets & Identity Without a CMDB

**Status:** Planning outline only — no slide visuals created yet. This is the discussion flow for the ~10-minute core section of the talk, sitting between the intro slides and the takeaways wrap-up.

**Session:** SEC1053 — "The other AI: Assets and Identity. Using Splunk to keep in check"
**Format:** Theater Session, 20 minutes total (Wed Sep 16, 3:00–3:20 PM MDT)
**Maps to takeaways** (see `SEC1053.md`):
- T1 — Continuous asset discovery and risk tracking
- T2 — Automated governance workflows for CAF / NIST CSF compliance
- T3 — Turning compliance reports into proactive, automated security actions

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

## Slide 6 — The Hard Part: Identity Correlation, Not Collection

The real challenge isn't gathering the data, it's correlating hostname/IP/MAC/cloud-instance-ID into one canonical asset identity over time — through DHCP churn, VPN NAT, ephemeral instances. Introduce the need for a normalization schema here.

## Slide 7 — Building the "Poor Man's CMDB" in Splunk

Scheduled searches normalize and push identity data into KV Store lookups — continuously refreshed, always current. Reference Asset and Risk Intelligence (ARI) as Splunk's productized version of this exact pattern.

## Slide 8 — Architecture Walkthrough

Data flow diagram: sources → normalization searches → KV Store lookup → ES Asset framework → enriched notable events. Show the actual lookup schemas here — `asset_lookup_schema.json` / `identity_lookup_schema.json` and the ES 8.5.1 YAML templates already in `conf26/SEC1053/Proof_of_concept/`.

## Slide 9 — Bridge to Takeaway 2: Governance Gets Measurable

Once you have continuous coverage, map it directly to CAF Principle A3 (Asset Management) and NIST CSF ID.AM. Completeness, freshness, and ownership become auditable KPIs instead of a point-in-time spreadsheet an auditor has to take on faith.

## Slide 10 — Bridge to Takeaway 3: From Visibility to Automated Action

Tagged, risk-scored assets let you automate: rogue-asset detection when something unmanaged appears on the network, automatic ticket creation, dynamic risk re-scoring. The compliance report stops being a PDF and becomes a live trigger.

## Slide 11 — Recap & Handoff

"You don't need a CMDB — you need continuous, correlated identity." One-line summary that hands cleanly into the wrap-up slides tying back to all three official takeaways.

---

**Notes:**
- This arc builds toward all three takeaways in sequence: T1 → slides 2–8, T2 → slide 9, T3 → slide 10.
- Supporting artifacts already in the repo that slide 8 should reference: `Proof_of_concept/Splunk ES 8.5.1 Asset Lookup — YAML Template.yml`, `Proof_of_concept/Splunk ES 8.5.1 Identity Lookup — YAML Template.yml`, and the project's `asset_lookup_schema.json` / `identity_lookup_schema.json`.

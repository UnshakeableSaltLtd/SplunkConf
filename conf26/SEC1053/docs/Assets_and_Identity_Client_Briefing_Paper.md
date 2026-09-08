# Briefing Paper: Bringing Assets and Identity Under Control Without a CMDB or a Single Source of Truth

**Prepared by:** David Pollard, Unshakeable Salt Ltd
**Audience:** Client — CISO / Security Leadership / SOC Management
**Companion to:** Splunk .conf26 Session SEC1053, "The other AI: Assets and Identity. Using Splunk to keep in check"
**Status:** Draft for client discussion

---

## 1. Executive Summary

Most organisations do not have a trustworthy Configuration Management Database (CMDB). Of the ones that do, few trust it enough to act on it during an incident. Yet every meaningful security decision — how urgent is this alert, who owns this box, does this account belong to a real person, is this asset even supposed to be here — depends on knowing what you have and who is responsible for it.

This paper sets out a practical approach for building and sustaining Assets and Identity data good enough to run security operations on, in an estate that has **no CMDB, no agreed source of truth, multiple overlapping directories, and an unknown volume of unmanaged and shadow infrastructure**. It is written around three non-negotiable principles the client has asked us to design for:

1. The Security Operations Centre (SOC) must never become the de facto owner or custodian of asset and identity truth. It is a **consumer**, not a system of record.
2. The SOC must never rely on non-machine-readable artefacts — spreadsheets, Word documents, wiki pages — as its working copy of this data. Everything the SOC consumes must be structured, versioned, and machine-readable.
3. The programme must work in two phases: a **first-time population** exercise that gets the estate to a usable baseline, followed by a **business-owned, continuously maintained** state that the SOC simply draws from.

We also address two problems that are usually glossed over: reconciling **multiple, independent sources of fact** (for example several Active Directory forests inherited through acquisition), and formally distinguishing between an asset/identity that is a **known fact** (asserted by an authoritative business system) versus one that is merely **discovered** (surfaced by telemetry with no corroborating record) — each requiring a different confidence and risk treatment.

Where relevant we reference the approach being presented at Splunk .conf26 (session SEC1053), which treats Splunk Enterprise Security's asset and identity framework — optionally accelerated by Splunk Asset and Risk Intelligence (ARI) — as an **enrichment and consumption layer**, not a replacement CMDB.

---

## 2. The Problem, Stated Plainly

- **No CMDB, or one nobody trusts.** Manual entry drift, mergers and acquisitions, shadow IT, ephemeral cloud resources, and siloed ownership mean a CMDB — if one exists — is a stale snapshot of a moving estate.
- **No single authoritative directory.** Multiple Active Directory forests/domains (often from M&A), regional IT autonomy, and parallel cloud identity providers mean there is no one place that can answer "does this identity exist and is it active?"
- **Discovery gaps that are invisible, not just unmanaged.** Unmanaged BYOD, shadow SaaS, decommissioned-but-still-routable cloud resources, OT/IoT devices with no agent capability, contractor laptops, orphaned service accounts, and undocumented API integrations don't show up as a "known risk" on a register — they simply don't generate telemetry at all. Security incidents are rarely "the SOC missed the alert"; far more often, there was no telemetry source in that part of the estate to begin with.
- **Without this data, every alert is noise with a hostname attached.** No ownership, no business criticality, no way to set urgency, no way to tell a compromised finance server from a compromised test VM.

The UK National Cyber Security Centre's Cyber Assessment Framework makes this explicit under **Principle A3, Asset Management**: "everything required to deliver, maintain or support network and information systems necessary for the operation of essential functions is determined and understood," including "an accurate source of information" where asset data should carry "a confidence score or last-seen timestamp to reflect how stale or uncertain it is" ([NCSC CAF, Principle A3](https://www.ncsc.gov.uk/collection/cyber-assessment-framework/caf-objective-a-managing-security-risk/principle-a3-asset-management); [NCSC Asset Management guidance](https://www.ncsc.gov.uk/guidance/asset-management)). NIST CSF 2.0's **ID.AM (Asset Management)** category sets out the same expectation for US-aligned organisations, including maintained hardware/software inventories, mapped data flows, supplier inventories, and criticality-based prioritisation ([NIST CSF 2.0 Core, ID.AM](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf); [NIST CSF Identify function](https://www.nist.gov/cyberframework/identify)).

The market has a name for the discipline this paper describes: **Cyber Asset Attack Surface Management (CAASM)** — coined by Gartner, defined as aggregating data from across the existing tool estate (EDR, vulnerability scanners, CMDBs, cloud platforms, network monitoring) into one queryable, continuously updated inventory, rather than building yet another static register ([Tenable, "What is CAASM?"](https://www.tenable.com/cybersecurity-guide/learn/what-is-caasm); [Gartner CAASM market definition](https://www.gartner.com/reviews/market/cyber-asset-attack-surface-management)). That is the frame this paper adopts.

---

## 3. Guiding Principles

These are the constraints the design must satisfy, non-negotiably:

| Principle | What it means in practice |
|---|---|
| **SOC is a consumer, not the custodian** | The SOC never becomes the team people email to "get the asset list updated." It receives a governed, machine-readable feed and raises data-quality exceptions back to the business owner — it does not fix the data itself except as a logged, time-boxed emergency override. |
| **No spreadsheets in the SOC** | If a SOC analyst's working reference for an asset or identity is a spreadsheet, document, or wiki table, the design has failed. Everything the SOC touches must be structured (JSON/lookup/API/KV Store), versioned, and automatically refreshed. |
| **One authoritative owner per attribute, many consumers** | Different systems legitimately own different fields — HR owns employment status, a given AD domain owns its own computer objects and group membership, cloud tagging policy owns environment/owner tags. Downstream systems, including the SOC's tooling, are controlled consumers of that record, never a second master ([NHI Mgmt Group, "Who should own the single source of truth for user and device lifecycle data?"](https://nhimg.org/faq/who-should-own-the-single-source-of-truth-for-user-and-device-lifecycle-data/)). |
| **Facts and discoveries are treated differently** | A record asserted by a designated authoritative source is a *fact*. A record surfaced only by telemetry, with no corroborating authoritative source, is *discovered* and carries lower confidence until it is claimed or reconciled. |
| **Every entity carries a live confidence and risk score** | Never mix "we are sure this is accurate" with "this is dangerous" — track them as two separate, continuously recalculated scores per asset and per identity. |

---

## 4. Target Architecture: Where the Data Actually Lives

The architecture has four layers. The SOC only ever touches the last one.

```
 Authoritative "fact" sources          Discovery sources
 (business-owned systems of record)    (telemetry with no guaranteed record)
 ─────────────────────────────────      ─────────────────────────────────────
 • AD forest/domain 1, 2, 3...          • EDR / endpoint check-ins
 • HRIS (joiner/mover/leaver)           • DHCP leases, VPN/NAC logs
 • Cloud IAM / Entra ID                 • Passive network/traffic discovery
 • Cloud provider tags (AWS/Azure/GCP)  • Vulnerability scanner sweeps
 • MDM/UEM                              • Cloud API enumeration (untagged resources)
 • Existing CMDB fragments, if any      • DNS query logs
 • Procurement / asset lifecycle system • Cloud-native asset inventory APIs
        │                                        │
        └───────────────┬────────────────────────┘
                         ▼
          External Entity Registry (business-owned, not SOC-owned)
          • Normalises, deduplicates, assigns stable IDs
          • Applies explicit source precedence per field
          • Tags every record: fact vs discovered, source, confidence, last-seen
          • Computes composite risk score per asset/identity
                         │
                         ▼
        Curated, machine-readable published views
        (e.g. `assets_export`, `identities_export` — API or lookup-backed feed)
                         │
                         ▼
        SOC consumption layer: Splunk Enterprise Security
        asset & identity framework (optionally accelerated by
        Splunk Asset and Risk Intelligence) — enrichment only
```

This is the same shape recommended by Splunk's own documentation: asset and identity data should be collected from external systems (AD, LDAP, CMDBs, ServiceNow, cloud sources, scripted inputs) and delivered to Splunk Enterprise Security as lookups, which ES then merges, correlates, and uses for enrichment — Splunk ES is designed to consume and reconcile, not to be the primary lifecycle system for inventory governance ([Splunk, Manage assets and identities in Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-assets-and-identities-in-splunk-enterprise-security); [Splunk, Extract asset and identity data](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/asset-and-identity-management/extract-asset-and-identity-data-in-splunk-enterprise-security)).

Commercial CAASM tooling (e.g. Axonius) documents the same discipline as a repeatable pipeline — **Collect → Correlate → Normalize → Enrich → Model → Assess** — which maps directly onto the External Entity Registry layer above ([Axonius, "Behind Actionability: The Asset Intelligence Pipeline"](https://www.axonius.com/blog/behind-actionability-the-axonius-asset-intelligence-pipeline)).

---

## 5. Phase 1 — First-Time Population (Bootstrap)

Goal: reach a usable, machine-readable baseline once, without creating a second permanent SOC-owned inventory.

1. **Enumerate every candidate source.** Every AD forest/domain and its trust relationships, every IdP, the HRIS, every MDM/UEM, EDR, cloud account (per provider, per subscription/project), vulnerability scanner, existing CMDB fragments, and — critically — every legacy spreadsheet or document currently used informally. Legacy spreadsheets are inputs to be absorbed once, then formally retired, not maintained.
2. **Design the stable identifier scheme before importing anything.** Hostnames, IPs, and usernames all churn (DHCP, NAT, re-joins, name changes). Assign immutable internal IDs and treat `ip`/`mac`/`nt_host`/`dns` (assets) and `identity`/`email` (identities) as *matching keys*, not permanent identity.
3. **Load authoritative facts first, with explicit source precedence.** If two AD domains, an HRIS, and a cloud tagging policy all assert a value for the same field, decide in advance which one wins, per field — not a blanket "last write wins."
4. **Run discovery sweeps to surface what nothing has claimed.** Network/passive discovery, EDR telemetry, and cloud API enumeration will surface assets and identities with no authoritative record at all. These become **discovered, unclaimed** entities — the true "unknown unknowns" — and are the highest-priority output of this phase, not a footnote to it.
5. **Hold a reconciliation exercise with business owners**, not the SOC, to assign ownership to every unclaimed discovered entity. The SOC's role here is to hand over the list and facilitate the meeting, not to decide who owns what.
6. **Retire the spreadsheets.** Once their content is absorbed into the registry, decommission them formally — do not let a "temporary" copy survive in a SharePoint folder.

---

## 6. Phase 2 — Ongoing Maintenance (Business-Owned, SOC-Consumed)

Goal: keep the registry current without the SOC doing any of the maintenance work.

- **RACI by source system.** Each AD domain's own administrators own their domain's computer and account objects; HR owns joiner/mover/leaver triggers; cloud platform teams own tag governance; procurement/finance own asset lifecycle events (purchase, transfer, disposal). The SOC is not the "R" or "A" for any of these.
- **Automated sync, not re-entry.** Scheduled jobs — run by platform/IT teams, not the SOC — pull from each source, normalise, deduplicate, and republish the curated views on a fixed schedule.
- **Event-driven triggers, not periodic dumps alone.** HR terminations should retire identities same-day; asset decommissioning in the CMDB or cloud console should retire assets same-day. Continuous discovery matters more than a once-a-year inventory project precisely because the gap that matters is the one nobody has noticed yet.
- **A business-led Data Quality forum**, meeting on a fixed cadence, owning freshness/completeness SLAs. The SOC attends as a stakeholder — reporting gaps it has found through discovery and consuming the metrics — but does not chair it and does not own the remediation backlog.
- **The SOC edits nothing directly**, except a logged, time-boxed emergency override (e.g. urgently reprioritising an asset during an active incident), which is automatically reconciled back to the authoritative source afterwards, not left as a permanent SOC-side fork.

---

## 7. What the SOC Actually Consumes

The SOC's interface to this entire programme is a **curated, versioned, machine-readable feed** — never a document. In Splunk terms this is the asset and identity lookup framework (`assets_export` / `identities_export`-style publications feeding `SA-IdentityManagement`), optionally accelerated by Splunk Asset and Risk Intelligence, which continuously discovers and correlates assets and identities from data already flowing through Splunk with no additional agents required ([Splunk ARI product overview](https://www.splunk.com/en_us/products/splunk-asset-and-risk-intelligence-security-features.html); [Splunk ARI onboarding guide](https://help.splunk.com/en/security-offerings/splunk-asset-and-risk-intelligence/administer/1.0/getting-started-with-administration/splunk-asset-and-risk-intelligence-onboarding-guide-for-admins)).

The SOC's job with this data is strictly:

1. Correlate it against security telemetry to give every alert ownership, business criticality, and urgency context.
2. Use it to drive investigation and triage — not to author or hand-edit it.
3. Raise structured data-quality exceptions back to the business owner identified in the RACI when the feed is stale, contradictory, or missing an entity the SOC has independently observed.

---

## 8. Two Trust Classes: Fact vs Discovered

Every asset and identity record in the registry must be explicitly tagged as one of:

- **Fact** — asserted by a system the business has formally designated as the authoritative source of record for that attribute (a specific AD domain for its own computer/account objects, HR for employment status, an enforced cloud tagging policy for environment/owner tags). Facts still carry a freshness timestamp and are down-weighted if stale.
- **Discovered** — surfaced by a detection or telemetry mechanism (network scan, EDR, passive traffic capture, cloud API enumeration, DNS logs) with **no corroborating fact**. Classic examples: an unmanaged BYOD device, an orphaned service account nobody remembers creating, a decommissioned-but-still-routable VPN concentrator, undocumented shadow SaaS.

A discovered entity is not a permanent state — it should be actively driven toward one of two outcomes: **claimed** (a business owner is assigned and it is reconciled into an authoritative source, converting it to a fact) or **confirmed and retired** (verified benign or decommissioned). Until either happens, it stays flagged as discovered and — as covered next — carries an automatic risk uplift for remaining unowned.

---

## 9. Risk and Confidence Scoring

Track **two separate, continuously recalculated scores** per asset and per identity — do not collapse them into one number.

### 9.1 Confidence score — "how sure are we this record is right, right now?"

| Input | Effect |
|---|---|
| Source authority tier | Fact from a designated system of record scores higher than discovered-only |
| Corroboration count | Independently agreeing sources (e.g. AD *and* EDR *and* cloud tag all agree) raise confidence |
| Freshness / last-seen timestamp | Confidence decays the longer since last confirmed sighting |
| Historical stability | Records that have been stable over time score higher than ones that flip frequently |

This directly operationalises NCSC's own guidance that asset data should carry "a confidence score or last-seen timestamp… to reflect how stale or uncertain the information is" ([NCSC Asset Management guidance](https://www.ncsc.gov.uk/guidance/asset-management)).

### 9.2 Risk score — "how dangerous is this entity if it is compromised, misused, or wrong?"

| Input | Effect |
|---|---|
| Exposure | Internet-facing, privileged access, regulated data (e.g. PCI domain) raise risk |
| Business criticality | Tied to `bunit`/`category`/`priority`-style business context, not just technical attributes |
| Known vulnerabilities / control gaps | Missing AV, no time-sync, no EDR coverage, unpatched CVEs |
| Anomalous behaviour | Deviation from established baseline for that asset/identity |
| **Unowned/discovered status itself** | An entity nobody has claimed is inherently higher risk than an identical entity with a confirmed owner — the absence of ownership is itself a risk signal, not a neutral unknown |

### 9.3 Composite scoring approach

Rather than a single static field, combine multiple risk signals into a dynamic composite that grows and decays over time — the same approach Splunk Enterprise Security's risk-based alerting uses, where a finding-based detection sums risk-index events for a given entity into an aggregated risk score that rises and falls with recent activity ([Splunk, Create finding-based detections in Enterprise Security](https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/detections/create-finding-based-detections-in-splunk-enterprise-security)). Splunk Asset and Risk Intelligence extends this pattern specifically to assets: risk rules run continuously against asset activity and combine into a **composite risk score** that grows and shrinks with the underlying signal ([Splunk, "Logs Are for Campfires: ARI"](https://www.splunk.com/en_us/blog/security/splunk-asset-risk-intelligence-no-vulnerability-undiscovered.html)).

For comparison, other vendors in the same space use analogous constructs worth being aware of when benchmarking a target design: Tenable combines an Asset Criticality Rating with a dynamic Vulnerability Priority Rating into an overall Asset Exposure Score ([Tenable One data sheet](https://www.content.shi.com/cms-content/accelerator/media/pdfs/tenable/tenable-121525-tenable-one-data-sheet.pdf)), and identity-specific risk profiling approaches synthesise access, privilege, and behavioural signals into a per-identity risk rating for zero-trust policy decisions ([Deepwatch, Identity Risk Profiles](https://www.deepwatch.com/glossary/identity-risk-profiles/)).

**Recommendation:** adopt a weighted composite score per asset and per identity, computed from the inputs above, recalculated continuously (not batch-refreshed weekly), with confidence and risk stored and surfaced as two distinct values so an analyst can immediately see both "how sure are we" and "how bad would it be."

---

## 10. Governance and Roles (Summary RACI)

| Activity | Responsible | Accountable | Consulted | Informed |
|---|---|---|---|---|
| Maintaining AD domain objects | Each domain's platform/IT team | Domain owner | — | Entity registry pipeline |
| HR joiner/mover/leaver feed | HR systems team | HR data owner | IAM team | Entity registry pipeline |
| Cloud tag governance | Cloud platform team | Cloud platform lead | Security architecture | Entity registry pipeline |
| Registry normalisation, precedence, scoring | Data/platform engineering | Data owner (business, not SOC) | SOC (as consumer) | All source teams |
| Discovery sweeps and unclaimed-entity triage | SOC + platform engineering jointly | Business asset owner assigned per entity | SOC | Data Quality forum |
| Consuming enriched data for triage/investigation | SOC analysts | SOC manager | — | — |
| Data-quality exception reporting | SOC | Data Quality forum | Source system owner | — |

---

## 11. Mapping to Regulatory Drivers

| Framework requirement | How this design satisfies it |
|---|---|
| NCSC CAF Principle A3.a — assets identified, inventoried, kept up to date, prioritised, with assigned responsibility ([NCSC CAF Principle A3](https://www.ncsc.gov.uk/collection/cyber-assessment-framework/caf-objective-a-managing-security-risk/principle-a3-asset-management)) | Continuous discovery + business-owned registry + explicit RACI + confidence/freshness scoring replaces a point-in-time inventory with an auditable, always-current one |
| NIST CSF 2.0 ID.AM-01/02 — hardware and software/service inventories maintained ([NIST CSF 2.0](https://nvlpubs.nist.gov/nistpubs/CSWP/NIST.CSWP.29.pdf)) | Multi-source discovery + AD/cloud/EDR facts feeding the registry |
| NIST CSF 2.0 ID.AM-05 — assets prioritised by classification, criticality, impact | Composite risk score, `bunit`/`category`/`priority` business context |
| NIST CSF 2.0 ID.AM-08 — systems/data managed through their lifecycle | HR and asset-lifecycle event triggers (joiner/mover/leaver, provision/decommission) |

Completeness, freshness, and ownership become auditable, machine-derived KPIs an auditor can query, rather than a point-in-time spreadsheet taken on faith.

---

## 12. The .conf26 Proposal: Two Implementation Options

Both options implement the same architecture in Section 4; they differ in how much is built versus bought.

| Option | Description | Best fit |
|---|---|---|
| **A — Lean external entity registry** | A small external system (e.g. PostgreSQL) as the entity registry, with scripted/scheduled sync jobs pulling from AD, HR, cloud APIs, and discovery tooling, applying precedence and stable IDs, and publishing curated `assets_export`/`identities_export` views into Splunk Enterprise Security's asset and identity lookups | Organisations wanting full control of reconciliation logic and no dependency on a new commercial licence; higher build/ maintenance effort |
| **B — Splunk Asset and Risk Intelligence (ARI)** | Productised version of the same discovery → correlation → composite risk-scoring pattern, using data already ingested into Splunk, requiring no additional agents, with built-in compliance framework mappings and integration into Splunk Enterprise Security | Organisations already invested in Splunk who want faster time-to-value and vendor-maintained correlation/scoring logic |

Both options preserve every principle in Section 3: the SOC still consumes rather than owns, and Splunk Enterprise Security remains an **enrichment layer**, not the CMDB replacement — its asset and identity framework was built to merge and enrich externally-sourced data, not to generate that data from nothing ([Splunk, Add asset and identity data to Enterprise Security](https://help.splunk.com/splunk-enterprise-security-8/administer/8.1/asset-and-identity-management/add-asset-and-identity-data-to-splunk-enterprise-security)).

---

## 13. Anti-Patterns to Avoid

- Letting the SOC become the only editable master for lifecycle inventory.
- Feeding raw, conflicting multi-source data straight into Splunk ES without upstream normalisation and precedence rules.
- Over-building a full ITIL-style CMDB when the actual requirement is security enrichment.
- Relying on hostname alone as a durable key.
- Blending "observed telemetry fact" and "authoritative metadata" into a single undifferentiated field.
- Letting spreadsheets survive "temporarily" after the registry goes live.
- Treating an unclaimed discovered entity as a neutral unknown rather than an active risk signal.

---

## 14. Recommended Next Steps

1. Confirm source inventory (all AD domains, HR, cloud accounts, discovery tooling, existing spreadsheets) and agree field-level precedence rules.
2. Stand up the external entity registry (Option A or B) and run the first discovery sweep.
3. Run the ownership reconciliation workshop for unclaimed discovered entities.
4. Publish the first curated feed into Splunk Enterprise Security and validate merge behaviour before broad rollout (duplicate usernames, multi-homed assets, NAT/private overlap).
5. Stand up the business-led Data Quality forum and retire legacy spreadsheets.
6. Review composite risk/confidence scoring thresholds with the SOC after the first full reporting cycle.

---

*This briefing paper is a companion document to Splunk .conf26 session SEC1053. It is intended as a discussion draft — architecture, thresholds, and the build-vs-buy choice in Section 12 should be finalised against the client's actual estate before implementation begins.*

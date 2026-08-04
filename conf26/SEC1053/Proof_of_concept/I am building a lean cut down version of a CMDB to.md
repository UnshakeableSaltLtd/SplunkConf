<img src="https://r2cdn.perplexity.ai/pplx-full-logo-primary-dark%402x.png" style="height:64px;margin-right:32px"/>

# I am building a lean cut down version of a CMDB to hold an inventory of all my 'assets' and 'identities' that I will be using with Splunk Enterprise Security.

I am unsure where I should host these - potentially inside splunk, but also like the idea of having it external and updated by scripts and by Splunk itself.   What would be recommended and are there any high level designs that would be deemed to be best practice

For a lean CMDB to support Splunk Enterprise Security, the usual best-practice pattern is to keep the authoritative asset and identity data **outside Splunk**, then feed curated, normalized copies into ES for enrichment and correlation. Splunk ES is very good at **merging, enriching, and operationalizing** asset/identity data through lookups and KV Store, but it is usually not the best long-term system of record for your inventory itself.[^1][^2]

## Short recommendation

Use a **hybrid model**: an external source of truth for assets and identities, plus Splunk ES as the enrichment/cache layer for security workflows. Splunk’s own guidance emphasizes collecting asset and identity data from external systems such as AD, LDAP, CMDBs, ServiceNow, cloud sources, DB Connect, scripted inputs, or indexed events, then formatting that data as lookups for ES to process.[^2]

If you are building a lean version rather than a full ITSM CMDB, think of it as an **entity registry** rather than a classic CMDB: keep only the fields that materially improve ES context, urgency, correlation, filtering, and investigations. Splunk ES expects structured asset and identity fields, supports multiple lookup sources, and merges them according to policies and key fields you define.[^3][^1][^2]

## Why not make Splunk the master?

Splunk ES stores merged asset and identity data using its framework and updates that merged data into KV Store-backed structures, including delayed deletion handling and `outputlookup append=T` during processing. That makes Splunk very useful as the operational enrichment layer, but it also shows ES is oriented around **consuming and reconciling** data rather than acting as the primary lifecycle system for inventory governance.[^4][^5][^1]

Splunk also expects you to define lookup sources, merge ranking, matching fields, and correlation behavior, which is exactly the shape of a downstream consumer integrating multiple authorities. In practice, if scripts, cloud APIs, AD, vulnerability tools, MDM, EDR, and discovery scans all contribute inventory, you want that reconciliation logic in a controlled external data model first, then publish a clean ES-friendly view.[^6][^1][^2]

## Recommended architecture

A good high-level design is:


| Layer | Role | Recommendation |
| :-- | :-- | :-- |
| Authoritative sources | Real owners of truth | Active Directory, LDAP, cloud inventory, EDR, CMDB, HR/IAM, MDM, vulnerability platforms remain the source systems. [^2] |
| External entity store | Lean master registry | Use a small database or service that normalizes assets and identities, assigns stable IDs, tracks source confidence, and exposes export/API views. |
| Integration jobs | Sync and reconciliation | Scripts/jobs pull from source systems, deduplicate, standardize names, and publish ES lookups on a schedule. [^2] |
| Splunk ES entity layer | Security enrichment | Upload or generate asset/identity lookups in `SA-IdentityManagement`, let ES merge, correlate, and enrich events. [^1][^2] |
| Analyst workflow | Investigation/use in ES | Analysts use enriched notables, urgency, filtering, and investigations inside ES rather than maintaining inventory there. [^7][^1] |

## Best-practice design principles

- **External system of record, Splunk as consumer/enricher.** This keeps inventory maintainable, scriptable, and reusable by other tools, while still aligning with how ES is designed to ingest and merge entity data.[^1][^2]
- **Multiple sources, one published golden view.** Splunk supports multiple asset and identity lookup sources and merges them, but it is better to reduce ambiguity before ES sees the data.[^3][^1]
- **Keep the schema minimal.** Splunk’s expected fields already show what is worth carrying: asset keys like `ip`, `mac`, `nt_host`, `dns`, plus business context such as `owner`, `priority`, `bunit`, `category`; and identity keys such as `identity`, `email`, `managedBy`, `priority`, `bunit`, and `category`.[^2]
- **Use stable identifiers internally.** Even if ES mainly matches on lookup fields, your external registry should maintain immutable IDs for assets and identities so merges and history are not dependent on hostname or username churn.
- **Track source precedence explicitly.** Splunk ES lets you rank merge order for assets and identities, which fits a model where some sources are authoritative for ownership, others for technical attributes, and others for status.[^1]
- **Publish only security-relevant fields to ES.** Your external registry can keep richer metadata, but ES should get the curated subset that helps enrichment and urgency.


## A practical lean schema

For a cut-down design, I would split it into two canonical entities and one relationship layer.

### Assets

Start with:

- Stable asset ID.
- `ip`, `mac`, `nt_host`, `dns` as match keys where applicable; ES requires at least one key field such as `ip`, `mac`, `nt_host`, or `dns` for assets.[^2]
- Owner identity reference.
- Business unit, category, priority.
- Environment, location/zone, cloud account/subscription/project.
- Security state flags you actually use, such as managed/unmanaged, EDR present, server/workstation, production/non-production.


### Identities

Start with:

- Stable identity ID.
- Login names and aliases mapped to ES `identity`.
- Email, first/last name, manager, department/business unit.
- Privilege classification, watchlist flag, priority.
- Employment state dates if you care about joiner/mover/leaver context; ES supports fields such as `startDate` and `endDate`.[^2]


### Relationships

Keep:

- Asset-to-owner.
- Asset-to-service/application.
- Identity-to-manager.
- Identity-to-role/classification.
- Asset-to-zone/network boundary.

Splunk ES can use categories, priorities, business units, watchlists, and zones in enrichment/correlation, so those are high-value fields for your published output.[^1][^2]

## Where to host it

For a lean estate, the best host is usually one of these:


| Option | Fit | Pros | Cons |
| :-- | :-- | :-- | :-- |
| PostgreSQL or MariaDB | Best default | Simple, scriptable, versionable, easy to back up, easy to export CSV/API views | You must design the model and sync jobs |
| ServiceNow or existing CMDB | Best if already present | Existing governance and workflows, native source ownership | Often too heavy if you want “lean” |
| Git-managed YAML/CSV plus build scripts | Good for very small environments | Extremely simple, auditable, easy to automate | Weak for joins, history, multi-writer updates |
| Splunk-only KV Store / lookups | Acceptable as cache only | Native to ES, easy to consume in detections | Not ideal as master inventory, weaker external reuse and lifecycle control [^1][^4] |

If you are already comfortable with automation and Linux, a small PostgreSQL service with Python/Ansible sync jobs is probably the cleanest middle ground. It gives you proper keys, reconciliation logic, and change control, while still making it easy to publish CSVs or API outputs that ES can ingest.

## Publish pattern into Splunk ES

A clean pattern is:

1. Pull from source systems into your external entity store.
2. Normalize and deduplicate.
3. Resolve collisions using source precedence rules.
4. Generate two published views: `assets_export` and `identities_export`.
5. Deliver those to ES as lookup-backed feeds.
6. Let ES merge and build its expanded lookups/KV Store for correlation.[^1][^2]

Splunk supports file-based lookups, scripted inputs, DB Connect, add-ons, and searches that generate lookups, and expects those lookups to live under `SA-IdentityManagement` when configured for the framework.  The framework then manages matching fields, lookup policies, merge ranking, and correlation setup in ES.[^2][^1]

## What “best practice” looks like

A defensible high-level design would be:

- **System of record outside Splunk.**
- **Curated exports into ES, not raw multi-source chaos.**
- **Minimal schema with stable IDs and explicit source precedence.**
- **Automated updates only; avoid manual editing in Splunk except emergency overrides.**
- **Use ES correlation selectively by sourcetype if needed, rather than turning on everything blindly.** Splunk documents selective correlation setup as a supported option.[^1]
- **Test merge outcomes regularly with ES search preview** before broad rollout, especially for duplicate usernames, multi-homed assets, NAT/private overlap, and naming collisions.[^1]
- **Use entity zones if you have overlapping private IP space.** Splunk supports `cim_entity_zone` for this scenario.[^2][^1]


## Anti-patterns to avoid

- Using Splunk as the only editable master database for all lifecycle inventory.
- Feeding raw, conflicting source data directly into ES without upstream normalization.
- Over-modeling like a full ITIL CMDB when you only need security enrichment.
- Relying on hostname alone as a durable key.
- Not separating “observed telemetry facts” from “authoritative metadata”.
- Letting too many people hand-edit CSVs with no reconciliation rules.


## My practical recommendation

I would recommend this specific pattern for your use case:

- Build a **small external entity registry** in PostgreSQL.
- Ingest from AD/IAM, endpoint tooling, cloud APIs, and any existing CMDB or inventory source.
- Maintain canonical `asset` and `identity` records with source precedence and timestamps.
- Publish ES-compatible lookup exports on a schedule.
- Import those into Splunk Enterprise Security as the operational enrichment layer.[^2][^1]

That gives you the flexibility you want—updated by scripts and optionally by Splunk-derived observations—without turning ES into the primary database. It is also the design most aligned with Splunk’s documented framework, where ES consumes external asset and identity data, merges it, and uses it for correlation and context.[^1][^2]

## Starter blueprint

If helpful, I can next produce one of these:

- a **reference schema** for `assets`, `identities`, and relationships;
- a **high-level architecture diagram** for the sync flow;
- a **sample Splunk export/search pattern** for publishing to ES lookups;
- or a **decision matrix** comparing PostgreSQL vs KV Store vs ServiceNow for your environment.
<span style="display:none">[^10][^11][^12][^13][^14][^15][^8][^9]</span>

<div align="center">⁂</div>

[^1]: https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-assets-and-identities-in-splunk-enterprise-security

[^2]: https://help.splunk.com/splunk-enterprise-security-8/administer/8.1/asset-and-identity-validation/configure-asset-and-identity-correlation-in-splunk-enterprise-security

[^3]: https://www.splunk.com/en_us/blog/security/asset-identity-for-splunk-enterprise-security-part-1-contextualizing-systems.html

[^4]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.5/asset-and-identity-validation/lookups-that-store-merged-asset-and-identity-data-in-splunk-enterprise-security

[^5]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/asset-and-identity-management/add-asset-and-identity-data-to-splunk-enterprise-security

[^6]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.0/asset-and-identity-management/extract-asset-and-identity-data-in-splunk-enterprise-security

[^7]: https://help.splunk.com/en/splunk-enterprise-security-7/administer/7.2/asset-and-identity-management/manage-assets-and-identities-to-enrich-notables-in-splunk-enterprise-security

[^8]: https://dev.splunk.com/enterprise/docs/devtools/enterprisesecurity/assetandidentityframework/

[^9]: https://www.reddit.com/r/Splunk/comments/1k0mxah/adding_identity_and_asset_lookups_in_splunk_es/

[^10]: https://www.splunk.com/en_us/blog/security/asset-identity-for-splunk-enterprise-security-part-2-adding-additional-attributes-to-assets.html

[^11]: https://aws.amazon.com/marketplace/pp/prodview-gnykoxx4z6ubo

[^12]: https://lantern.splunk.com/Security_Use_Cases/Assets_and_Identities/Tuning_Enterprise_Security_assets_and_identities

[^13]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.2/kv-store-collections-in-splunk-enterprise-security

[^14]: https://help.splunk.com/splunk-enterprise-security-8/administer/8.1/asset-and-identity-management/add-asset-and-identity-data-to-splunk-enterprise-security

[^15]: https://help.splunk.com/en/splunk-enterprise-security-8/administer/8.4/threat-intelligence/threat-intelligence-kv-store-collections-in-splunk-enterprise-security


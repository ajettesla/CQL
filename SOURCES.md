# Source Register

Research baseline: **19 November 2026**.

This repository uses official CrowdStrike Falcon LogScale documentation as the authority for syntax, function behavior, product support, and version compatibility. Community and independent sources are included as secondary explanations and practical examples.

## Official CrowdStrike Falcon LogScale Documentation

### Query Language & Syntax

- [CrowdStrike Query Language (CQL) Overview](https://library.humio.com/data-analysis/crowdstrike-query-language.html)
- [Query Language Syntax](https://library.humio.com/data-analysis/query-language-syntax.html)
- [Query Functions Reference](https://library.humio.com/data-analysis/query-functions.html)
- [CrowdStrike Query Language Grammar Subset](https://library.humio.com/data-analysis/crowdstrike-query-language-grammar-subset.html)
- [Writing Queries](https://library.humio.com/data-analysis/write-queries.html)
- [Query Examples Library](https://library.humio.com/data-analysis/examples.html)

### Functions by Category

#### Filtering Functions
- [in() Function](https://library.humio.com/data-analysis/functions-in.html)
- [test() Function](https://library.humio.com/data-analysis/functions-test.html)
- [cidr() Function](https://library.humio.com/data-analysis/functions-cidr.html)
- [match() Function](https://library.humio.com/data-analysis/functions-match.html)
- [regex() Function](https://library.humio.com/data-analysis/functions-regex.html)

#### Transformation Functions
- [format() Function](https://library.humio.com/data-analysis/functions-format.html)
- [concat() Function](https://library.humio.com/data-analysis/functions-concat.html)
- [split() / splitString() Function](https://library.humio.com/data-analysis/functions-split.html)
- [lower() / upper() Functions](https://library.humio.com/data-analysis/functions-lower.html)
- [replace() Function](https://library.humio.com/data-analysis/functions-replace.html)
- [eval() Function](https://library.humio.com/data-analysis/functions-eval.html)

#### Aggregation Functions
- [groupBy() Function](https://library.humio.com/data-analysis/functions-groupby.html)
- [count() Function](https://library.humio.com/data-analysis/functions-count.html)
- [sum() Function](https://library.humio.com/data-analysis/functions-sum.html)
- [avg() Function](https://library.humio.com/data-analysis/functions-avg.html)
- [stats() Function](https://library.humio.com/data-analysis/functions-stats.html)
- [collect() Function](https://library.humio.com/data-analysis/functions-collect.html)
- [top() Function](https://library.humio.com/data-analysis/functions-top.html)
- [bucket() Function](https://library.humio.com/data-analysis/functions-bucket.html)
- [timeChart() Function](https://library.humio.com/data-analysis/functions-timechart.html)

#### Parsing Functions
- [parseJson() Function](https://library.humio.com/data-analysis/functions-parsejson.html)
- [kvParse() Function](https://library.humio.com/data-analysis/functions-kvparse.html)

#### Enrichment Functions
- [ipLocation() Function](https://library.humio.com/data-analysis/functions-iplocation.html)
- [asn() Function](https://library.humio.com/data-analysis/functions-asn.html)
- [rdns() Function](https://library.humio.com/data-analysis/functions-rdns.html)
- [geoHash() Function](https://library.humio.com/data-analysis/functions-geohash.html)
- [match() for Lookup Tables](https://library.humio.com/data-analysis/functions-match.html)
- [join() Function](https://library.humio.com/data-analysis/functions-join.html)
- [selfJoin() Function](https://library.humio.com/data-analysis/functions-selfjoin.html)
- [selfJoinFilter() Function](https://library.humio.com/data-analysis/functions-selfjoinfilter.html)
- [readFile() Function](https://library.humio.com/data-analysis/functions-readfile.html)
- [defineTable() Function](https://library.humio.com/data-analysis/functions-definetable.html)

#### Visualization & Output Functions
- [table() Function](https://library.humio.com/data-analysis/functions-table.html)
- [select() Function](https://library.humio.com/data-analysis/functions-select.html)
- [rename() Function](https://library.humio.com/data-analysis/functions-rename.html)
- [drop() Function](https://library.humio.com/data-analysis/functions-drop.html)
- [sort() Function](https://library.humio.com/data-analysis/functions-sort.html)
- [head() / tail() Functions](https://library.humio.com/data-analysis/functions-head.html)
- [formatTime() Function](https://library.humio.com/data-analysis/functions-formattime.html)

### Query Joins & Lookups
- [Query Joins Methods: Ad-Hoc Tables](https://library.humio.com/data-analysis/query-joins-methods-adhoc-tables.html)
- [join() vs defineTable() + match()](https://library.humio.com/data-analysis/query-joins-methods-adhoc-tables.html#query-joins-methods-adhoc-tables-join)
- [Lookup Files](https://library.humio.com/data-analysis/lookup-files.html)

### Data Management & Ingestion
- [Getting Data In](https://library.humio.com/data-management/getting-data-in.html)
- [Parsing Data](https://library.humio.com/data-management/parse-data.html)
- [CrowdStrike Parsing Standard 1.2](https://library.humio.com/data-management/crowdstrike-parsing-standard.html)
- [Manage Repositories and Views](https://library.humio.com/data-management/manage-repositories-and-views.html)
- [Tagged Fields](https://library.humio.com/data-management/tagged-fields.html)

### Dashboards & Widgets
- [Data Visualization](https://library.humio.com/data-analysis/data-visualization.html)
- [Dashboard Creation](https://library.humio.com/data-analysis/create-dashboards.html)
- [Widget Types](https://library.humio.com/data-analysis/widget-types.html)
- [Time Controls and Filters](https://library.humio.com/data-analysis/dashboard-time-controls.html)
- [Sharing and Scheduled Reports](https://library.humio.com/data-analysis/sharing-scheduled-reports.html)

### Performance & Optimization
- [Query Optimization](https://library.humio.com/data-analysis/query-optimization.html)
- [LogScale Internal Architecture](https://library.humio.com/concepts/logscale-internal-architecture.html)
- [Limits and Standards](https://library.humio.com/administration/limits-and-standards.html)

### CrowdStrike Event Dictionaries (Official)
- [CrowdStrike Events Dictionary](https://falcon.crowdstrike.com/documentation/events-dictionary)
- [Windows Event Types](https://falcon.crowdstrike.com/documentation/events-dictionary/windows)
- [Linux Event Types](https://falcon.crowdstrike.com/documentation/events-dictionary/linux)
- [macOS Event Types](https://falcon.crowdstrike.com/documentation/events-dictionary/macos)
- [Container Event Types](https://falcon.crowdstrike.com/documentation/events-dictionary/containers)
- [Kubernetes Event Types](https://falcon.crowdstrike.com/documentation/events-dictionary/kubernetes)

### API & Automation
- [Search API](https://library.humio.com/api/search-api.html)
- [Ingest API](https://library.humio.com/api/ingest-api.html)
- [GraphQL API](https://library.humio.com/api/graphql-api.html)
- [humioctl CLI](https://library.humio.com/api/humioctl.html)

---

## CrowdStrike Community & GitHub

### Official CrowdStrike Repositories
- [CrowdStrike/logscale-community-content](https://github.com/CrowdStrike/logscale-community-content) — Official community content: parsers, dashboards, saved searches, packages
- [CrowdStrike/falconpy](https://github.com/CrowdStrike/falconpy) — FalconPy SDK for API automation

### Community Repositories (Practical Examples)
- [cs-shadowbq/CQL-Queries](https://github.com/cs-shadowbq/CQL-Queries) — Best practices, queries, and packages for CQL/LogScale. **Excellent practical reference** with real-world hunting queries, enrichment patterns, and dashboard examples.
- [straw-hat-kjones/cql-best-practices](https://github.com/straw-hat-kjones/cql-best-practices) — AI agent skill with 179 documentation files covering all CQL functions, threat hunting queries mapped to MITRE ATT&CK, event dictionaries for Windows/Linux/macOS/Container/Kubernetes (943 events total).

### CrowdStrike Community Discussions
- [CrowdStrike Falcon Community](https://community.crowdstrike.com/) — Official community forum for queries, detections, and best practices
- [LogScale Slack Community](https://humio-community.slack.com/) — Active practitioner community (invite via LogScale docs)

---

## Threat Intelligence & Framework References

### MITRE ATT&CK
- [MITRE ATT&CK Enterprise Matrix](https://attack.mitre.org/matrices/enterprise/) — Technique IDs referenced in hunting queries
- [MITRE ATT&CK for Cloud](https://attack.mitre.org/matrices/enterprise/cloud/) — Cloud-specific techniques

### CrowdStrike Intelligence
- [CrowdStrike Adversary Universe](https://www.crowdstrike.com/adversary-universe/) — Named adversary profiles
- [CrowdStrike Global Threat Report](https://www.crowdstrike.com/global-threat-report/) — Annual threat landscape

---

## Supplementary Learning Resources

### Official Training
- [Falcon LogScale Training](https://www.crowdstrike.com/services/education/) — Official instructor-led and on-demand courses
- [LogScale Certification](https://www.crowdstrike.com/services/education/certification/) — Falcon LogScale Administrator/Analyst certifications

### Blog Articles (Use as Supplementary Only)
- [CrowdStrike Blog - LogScale Category](https://www.crowdstrike.com/blog/category/logscale/) — Product updates and use cases
- [Humio Blog (Legacy)](https://humio.com/blog/) — Historical articles on query patterns

---

## Evidence Standard Reminder

Per [README.md](README.md#evidence-standard), every substantial example must cite:

1. **Official LogScale documentation URL** (primary authority)
2. **Product version** (LogScale Cloud / Self-Hosted version)
3. **Input example** (synthetic events via `createEvents()`)
4. **Exact query** (copy-pasteable CQL)
5. **Expected output** (table or description)
6. **Why each function is used** (classification + intent)
7. **Performance note** when relevant (tag filters, cardinality, join limits)

**Official documentation is the authority.** Community examples and GitHub repositories are useful for learning patterns and troubleshooting, but must not override current product documentation.
# Index — CrowdStrike Query Language (CQL) Complete Reference (v1.0)

## Quick Start & Navigation
- [README.md](README.md) — Overview, structure, quick navigation, evidence standard, labs
- [INDEX.md](INDEX.md) — This file: complete table of contents

---

## Chapter 1 — Foundations: Events, Repositories, Tagged Fields & Data Model
- [1.1 Why This Chapter Exists](Chapter1.md#11-why-this-chapter-exists)
- [1.2 What Is a LogScale Event?](Chapter1.md#12-what-is-a-logscale-event)
- [1.3 Where Do Events Come From?](Chapter1.md#13-where-do-events-come-from)
- [1.4 What Is a Repository?](Chapter1.md#14-what-is-a-repository)
- [1.5 Views: Curated Subsets of Repositories](Chapter1.md#15-views-curated-subsets-of-repositories)
- [1.6 Tagged Fields (`#tag`): The Performance Key](Chapter1.md#16-tagged-fields-tag-the-performance-key)
- [1.7 Internal Fields: `@timestamp`, `@rawstring`, `@id`](Chapter1.md#17-internal-fields-timestamp-rawstring-id)
- [1.8 Default Fields: `#repo`, `#type`, `host`, `source`](Chapter1.md#18-default-fields-repo-type-host-source)
- [1.9 Field Categories Summary Table](Chapter1.md#19-field-categories-summary-table)
- [1.10 Ingestion-Time vs Search-Time Processing](Chapter1.md#110-ingestion-time-vs-search-time-processing)
- [1.11 Parsers: Structure at Ingest](Chapter1.md#111-parsers-structure-at-ingest)
- [1.12 Filtering, Routing, Enrichment: Three Different Problems](Chapter1.md#112-filtering-routing-enrichment-three-different-problems)
- [1.13 Key Takeaways](Chapter1.md#113-key-takeaways)

---

## Chapter 2 — Query Syntax Fundamentals & Statement Ordering
- [2.1 The Pipeline Model](Chapter2.md#21-the-pipeline-model)
- [2.2 CQL vs SPL: Critical Syntax Differences](Chapter2.md#22-cql-vs-spl-critical-syntax-differences)
- [2.3 Generating Events: `createEvents()` and Repository Selection](Chapter2.md#23-generating-events-createevents-and-repository-selection)
- [2.4 Filtering: Tag Filters, Field Filters, `in()`, `test()`, `cidr()`](Chapter2.md#24-filtering-tag-filters-field-filters-in-test-cidr)
- [2.5 Transformation: Field Assignment (`:=`), `format()`, `regex()`, `split()`, `concat()`](Chapter2.md#25-transformation-field-assignment-format-regex-split-concat)
- [2.6 Aggregation: `groupBy()`, `count()`, `sum()`, `avg()`, `stats()`, `collect()`, `top()`, `bucket()`, `timeChart()`](Chapter2.md#26-aggregation-groupby-count-sum-avg-stats-collect-top-bucket-timechart)
- [2.7 Post-Processing: `sort()`, `head()`, `tail()`, `table()`, `select()`, `rename()`, `drop()`](Chapter2.md#27-post-processing-sort-head-tail-table-select-rename-drop)
- [2.8 Optimal Statement Ordering](Chapter2.md#28-optimal-statement-ordering)
- [2.9 Common Syntax Patterns](Chapter2.md#29-common-syntax-patterns)
- [2.10 What's Next](Chapter2.md#210-whats-next)

---

## Chapter 3 — CQL Functions Reference (Classified by Role)
- [3.1 Function Classification Badges](Chapter3.md#31-function-classification-badges)
- [3.2 Filtering Functions](Chapter3.md#32-filtering-functions)
  - [3.2.1 Tag Filters (`#tag=value`)](Chapter3.md#321-tag-filters-tagvalue)
  - [3.2.2 Field Filters (`field=value`)](Chapter3.md#322-field-filters-fieldvalue)
  - [3.2.3 `in()` — Set Membership](Chapter3.md#323-in--set-membership)
  - [3.2.4 `test()` — Expression Evaluation](Chapter3.md#324-test--expression-evaluation)
  - [3.2.5 `cidr()` — IP Range Matching](Chapter3.md#325-cidr--ip-range-matching)
  - [3.2.6 `match()` / `regex()` — Pattern Matching](Chapter3.md#326-match--regex--pattern-matching)
- [3.3 Transformation Functions](Chapter3.md#33-transformation-functions)
  - [3.3.1 `:=` — Field Assignment](Chapter3.md#331--field-assignment)
  - [3.3.2 `format()` — String Formatting](Chapter3.md#332-format--string-formatting)
  - [3.3.3 `concat()` — String Concatenation](Chapter3.md#333-concat--string-concatenation)
  - [3.3.4 `split()` / `splitString()` — String Splitting](Chapter3.md#334-split--splitstring--string-splitting)
  - [3.3.5 `lower()` / `upper()` — Case Conversion](Chapter3.md#335-lower--upper--case-conversion)
  - [3.3.6 `replace()` — String Replacement](Chapter3.md#336-replace--string-replacement)
  - [3.3.7 `eval()` — Expression Evaluation](Chapter3.md#337-eval--expression-evaluation)
- [3.4 Aggregation Functions](Chapter3.md#34-aggregation-functions)
  - [3.4.1 `groupBy()` — Core Aggregation](Chapter3.md#341-groupby--core-aggregation)
  - [3.4.2 `count()` / `sum()` / `avg()` / `min()` / `max()`](Chapter3.md#342-count-sum-avg-min-max)
  - [3.4.3 `stats()` — Multiple Aggregations](Chapter3.md#343-stats--multiple-aggregations)
  - [3.4.4 `collect()` — Collect Field Values](Chapter3.md#344-collect--collect-field-values)
  - [3.4.5 `top()` / `rare()` — Top/Bottom Values](Chapter3.md#345-top-rare--topbottom-values)
  - [3.4.6 `bucket()` — Time Bucketing](Chapter3.md#346-bucket--time-bucketing)
  - [3.4.7 `timeChart()` — Time Series Visualization](Chapter3.md#347-timechart--time-series-visualization)
- [3.5 Parsing Functions](Chapter3.md#35-parsing-functions)
  - [3.5.1 `parseJson()`](Chapter3.md#351-parsejson)
  - [3.5.2 `kvParse()`](Chapter3.md#352-kvparse)
  - [3.5.3 `splitString()`](Chapter3.md#353-splitstring)
  - [3.5.4 `regex()` with Named Groups](Chapter3.md#354-regex-with-named-groups)
- [3.6 Enrichment Functions](Chapter3.md#36-enrichment-functions)
  - [3.6.1 `ipLocation()`](Chapter3.md#361-iplocation)
  - [3.6.2 `asn()`](Chapter3.md#362-asn)
  - [3.6.3 `cidr()` (enrichment)](Chapter3.md#363-cidr-enrichment)
  - [3.6.4 `rdns()`](Chapter3.md#364-rdns)
  - [3.6.5 `geoHash()`](Chapter3.md#365-geohash)
  - [3.6.6 `match()` — Lookup Table Enrichment](Chapter3.md#366-match--lookup-table-enrichment)
  - [3.6.7 `join()` — Subquery Correlation](Chapter3.md#367-join--subquery-correlation)
  - [3.6.8 `selfJoin()` — High-Cardinality Self-Join](Chapter3.md#368-selfjoin--high-cardinality-self-join)
  - [3.6.9 `readFile()` — Lookup File Access](Chapter3.md#369-readfile--lookup-file-access)
- [3.7 Visualization & Output Functions](Chapter3.md#37-visualization--output-functions)
  - [3.7.1 `table()`](Chapter3.md#371-table)
  - [3.7.2 `select()`](Chapter3.md#372-select)
  - [3.7.3 `rename()`](Chapter3.md#373-rename)
  - [3.7.4 `drop()`](Chapter3.md#374-drop)
  - [3.7.5 `sort()`](Chapter3.md#375-sort)
  - [3.7.6 `head()` / `tail()`](Chapter3.md#376-head--tail)
  - [3.7.7 `formatTime()`](Chapter3.md#377-formattime)
- [3.8 Quick Function Lookup Table](Chapter3.md#38-quick-function-lookup-table)
- [3.9 What's Next](Chapter3.md#39-whats-next)

---

## Chapter 4 — Threat Hunting Patterns & MITRE ATT&CK Mapping
- [4.1 Why Threat Hunting in LogScale?](Chapter4.md#41-why-threat-hunting-in-logscale)
- [4.2 The Golden Rule: Tag Filters First](Chapter4.md#42-the-golden-rule-tag-filters-first)
- [4.3 Process Execution Hunting](Chapter4.md#43-process-execution-hunting)
  - [4.3.1 Suspicious Process Chains](Chapter4.md#431-suspicious-process-chains)
  - [4.3.2 Living Off The Land Binaries (LOLBins)](Chapter4.md#432-living-off-the-land-binaries-lolbins)
  - [4.3.3 PowerShell Encoded Commands](Chapter4.md#433-powershell-encoded-commands)
  - [4.3.4 WMI & WMIC Abuse](Chapter4.md#434-wmi--wmic-abuse)
- [4.4 Network Hunting](Chapter4.md#44-network-hunting)
  - [4.4.1 Beaconing Detection](Chapter4.md#441-beaconing-detection)
  - [4.4.2 Suspicious DNS](Chapter4.md#442-suspicious-dns)
  - [4.4.3 Non-Standard Ports](Chapter4.md#443-non-standard-ports)
- [4.5 Authentication & Access Hunting](Chapter4.md#45-authentication--access-hunting)
  - [4.5.1 Brute Force / Password Spray](Chapter4.md#451-brute-force--password-spray)
  - [4.5.2 Impossible Travel](Chapter4.md#452-impossible-travel)
  - [4.5.3 Privilege Escalation](Chapter4.md#453-privilege-escalation)
- [4.6 Persistence Hunting](Chapter4.md#46-persistence-hunting)
  - [4.6.1 Scheduled Tasks](Chapter4.md#461-scheduled-tasks)
  - [4.6.2 Registry Run Keys](Chapter4.md#462-registry-run-keys)
  - [4.6.3 Service Installation](Chapter4.md#463-service-installation)
- [4.7 Defense Evasion Hunting](Chapter4.md#47-defense-evasion-hunting)
  - [4.7.1 Log Clearing](Chapter4.md#471-log-clearing)
  - [4.7.2 Process Injection](Chapter4.md#472-process-injection)
  - [4.7.3 Signed Binary Proxy Execution](Chapter4.md#473-signed-binary-proxy-execution)
- [4.8 Discovery & Collection Hunting](Chapter4.md#48-discovery--collection-hunting)
- [4.9 Command & Control Hunting](Chapter4.md#49-command--control-hunting)
- [4.10 Exfiltration Hunting](Chapter4.md#410-exfiltration-hunting)
- [4.11 MITRE ATT&CK Mapping Table](Chapter4.md#411-mitre-attck-mapping-table)
- [4.12 Detection Engineering Best Practices](Chapter4.md#412-detection-engineering-best-practices)
- [4.13 Performance-Aware Hunting](Chapter4.md#413-performance-aware-hunting)
- [4.14 What's Next](Chapter4.md#414-whats-next)

---

## Chapter 5 — Joins, Lookups & Multi-Event Correlation
- [5.1 Why Correlation in LogScale?](Chapter5.md#51-why-correlation-in-logscale)
- [5.2 Join Types Overview](Chapter5.md#52-join-types-overview)
- [5.3 `join()` — Subquery Correlation](Chapter5.md#53-join--subquery-correlation)
  - [5.3.1 Inner Join](Chapter5.md#531-inner-join)
  - [5.3.2 Left Join](Chapter5.md#532-left-join)
  - [5.3.3 Right Join](Chapter5.md#533-right-join)
  - [5.3.4 Join Performance: The 200k Row Limit](Chapter5.md#534-join-performance-the-200k-row-limit)
- [5.4 `selfJoin()` — High-Cardinality Self-Join](Chapter5.md#54-selfjoin--high-cardinality-self-join)
  - [5.4.1 `selfJoinFilter()`](Chapter5.md#541-selfjoinfilter)
  - [5.4.2 When to Use `selfJoin()`](Chapter5.md#542-when-to-use-selfjoin)
- [5.5 Ad-Hoc Tables: `defineTable()` + `match()`](Chapter5.md#55-ad-hoc-tables-definetable--match)
  - [5.5.1 `defineTable()` Syntax](Chapter5.md#551-definetable-syntax)
  - [5.5.2 `match()` Syntax](Chapter5.md#552-match-syntax)
  - [5.5.3 `defineTable()` vs `join()`: Decision Guide](Chapter5.md#553-definetable-vs-join-decision-guide)
- [5.6 Lookup Files: `readFile()` + `match()`](Chapter5.md#56-lookup-files-readfile--match)
  - [5.6.1 CSV Lookup Files](Chapter5.md#561-csv-lookup-files)
  - [5.6.2 Enrichment Patterns](Chapter5.md#562-enrichment-patterns)
- [5.7 Correlation Patterns](Chapter5.md#57-correlation-patterns)
  - [5.7.1 Process Tree (Parent-Child)](Chapter5.md#571-process-tree-parent-child)
  - [5.7.2 Session Reconstruction](Chapter5.md#572-session-reconstruction)
  - [5.7.3 Lateral Movement](Chapter5.md#573-lateral-movement)
- [5.8 Multi-Cluster Views](Chapter5.md#58-multi-cluster-views)
- [5.9 What's Next](Chapter5.md#59-whats-next)

---

## Chapter 6 — Dashboards, Widgets & Visualization
- [6.1 Dashboard Creation Workflow](Chapter6.md#61-dashboard-creation-workflow)
- [6.2 Dashboard Layout & Time Controls](Chapter6.md#62-dashboard-layout--time-controls)
- [6.3 Widget Types Reference](Chapter6.md#63-widget-types-reference)
  - [6.3.1 Time Chart](Chapter6.md#631-time-chart)
  - [6.3.2 Bar / Column Chart](Chapter6.md#632-bar--column-chart)
  - [6.3.3 Pie Chart](Chapter6.md#633-pie-chart)
  - [6.3.4 Table](Chapter6.md#634-table)
  - [6.3.5 Single Value](Chapter6.md#635-single-value)
  - [6.3.6 Gauge](Chapter6.md#636-gauge)
  - [6.3.7 Sankey](Chapter6.md#637-sankey)
  - [6.3.8 World Map](Chapter6.md#638-world-map)
  - [6.3.9 Heat Map](Chapter6.md#639-heat-map)
  - [6.3.10 Event List](Chapter6.md#6310-event-list)
  - [6.3.11 Text / Markdown](Chapter6.md#6311-text--markdown)
- [6.4 Widget Configuration](Chapter6.md#64-widget-configuration)
- [6.5 Dashboard Filters & Parameters](Chapter6.md#65-dashboard-filters--parameters)
- [6.6 Sharing & Scheduled Reports](Chapter6.md#66-sharing--scheduled-reports)
- [6.7 Export Options](Chapter6.md#67-export-options)
- [6.8 Dashboard Best Practices](Chapter6.md#68-dashboard-best-practices)
- [6.9 What's Next](Chapter6.md#69-whats-next)

---

## Chapter 7 — Performance, Optimization & Reference
- [7.1 How LogScale Stores Data: Segment Files](Chapter7.md#71-how-logscale-stores-data-segment-files)
- [7.2 Tagged Fields: The Index Advantage](Chapter7.md#72-tagged-fields-the-index-advantage)
- [7.3 Query Execution Model](Chapter7.md#73-query-execution-model)
- [7.4 Cardinality Management](Chapter7.md#74-cardinality-management)
  - [7.4.1 Always Use `limit=` in `groupBy()`](Chapter7.md#741-always-use-limit-in-groupby)
  - [7.4.2 `limit=max` Only When Necessary](Chapter7.md#742-limitmax-only-when-necessary)
  - [7.4.3 Filter Before Transform](Chapter7.md#743-filter-before-transform)
- [7.5 Statement Ordering Performance](Chapter7.md#75-statement-ordering-performance)
- [7.6 Time Range Optimization](Chapter7.md#76-time-range-optimization)
- [7.7 `join()` vs `selfJoin()` vs `defineTable()` Performance](Chapter7.md#77-join-vs-selfjoin-vs-definetable-performance)
- [7.8 Live vs Scheduled Query Performance](Chapter7.md#78-live-vs-scheduled-query-performance)
- [7.9 Query Debugging](Chapter7.md#79-query-debugging)
- [7.10 Optimization Checklist](Chapter7.md#710-optimization-checklist)
- [7.11 Reference: Decision Tables & Cheat Sheets](Chapter7.md#711-reference-decision-tables--cheat-sheets)
  - [7.11.1 Filter Function Decision Table](Chapter7.md#7111-filter-function-decision-table)
  - [7.11.2 Aggregation Function Quick Reference](Chapter7.md#7112-aggregation-function-quick-reference)
  - [7.11.3 Join Method Decision Guide](Chapter7.md#7113-join-method-decision-guide)
  - [7.11.4 CQL vs SPL Syntax Cheat Sheet](Chapter7.md#7114-cql-vs-spl-syntax-cheat-sheet)
  - [7.11.5 Statement Ordering Cheat Sheet](Chapter7.md#7115-statement-ordering-cheat-sheet)
  - [7.11.6 Common Mistakes & Anti-Patterns](Chapter7.md#7116-common-mistakes--anti-patterns)
  - [7.11.7 Glossary](Chapter7.md#7117-glossary)
  - [7.11.8 File Inventory](Chapter7.md#7118-file-inventory)
  - [7.11.9 Version History](Chapter7.md#7119-version-history)
  - [7.11.10 Contributing](Chapter7.md#71110-contributing)

---

## Labs (Hands-On Practice)
- [Lab Data](labs/data/README.md) — Synthetic dataset schema and import instructions
- [Lab 01: Syntax Fundamentals](labs/01-syntax-fundamentals/README.md) — CQL vs SPL, field assignment, filtering
- [Lab 02: Function Practice](labs/02-function-practice/README.md) — groupBy, timeChart, ipLocation, match
- [Lab 03: Threat Hunting](labs/03-threat-hunting/README.md) — Brute force, beaconing, process chains
- [Lab 04: Dashboards](labs/04-dashboards/README.md) — Widget creation, parameters, sharing

---

## Reference Files
- [SOURCES.md](SOURCES.md) — Official LogScale docs, CrowdStrike community, GitHub references
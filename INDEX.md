# Index — CrowdStrike Query Language (CQL) Complete Reference (v1.0)

## Quick Start & Navigation
- [README.md](README.md) — Overview, structure, quick navigation, evidence standard, labs
- [CQL.md](CQL.md) — Complete single-file reference (all 9 chapters)

---

## Chapter 1 — Foundations: Events, Repositories, Tagged Fields & Data Model
- [1.1 Why This Chapter Exists](CQL.md#11-why-this-chapter-exists)
- [1.2 What Is a LogScale Event?](CQL.md#12-what-is-a-logscale-event)
- [1.3 Where Do Events Come From?](CQL.md#13-where-do-events-come-from)
- [1.4 What Is a Repository?](CQL.md#14-what-is-a-repository)
- [1.5 Views: Curated Subsets of Repositories](CQL.md#15-views-curated-subsets-of-repositories)
- [1.6 Tagged Fields (`#tag`): The Performance Key](CQL.md#16-tagged-fields-tag-the-performance-key)
- [1.7 Internal Fields: `@timestamp`, `@rawstring`, `@id`](CQL.md#17-internal-fields-timestamp-rawstring-id)
- [1.8 Default Fields: `#repo`, `#type`, `host`, `source`](CQL.md#18-default-fields-repo-type-host-source)
- [1.9 Field Categories Summary Table](CQL.md#19-field-categories-summary-table)
- [1.10 Ingestion-Time vs Search-Time Processing](CQL.md#110-ingestion-time-vs-search-time-processing)
- [1.11 Parsers: Structure at Ingest](CQL.md#111-parsers-structure-at-ingest)
- [1.12 Filtering, Routing, Enrichment: Three Different Problems](CQL.md#112-filtering-routing-enrichment-three-different-problems)
- [1.13 Key Takeaways](CQL.md#113-key-takeaways)

---

## Chapter 2 — Query Syntax Fundamentals & Statement Ordering
- [2.1 The Pipeline Model](CQL.md#21-the-pipeline-model)
- [2.2 CQL vs SPL: Critical Syntax Differences](CQL.md#22-cql-vs-spl-critical-syntax-differences)
- [2.3 Generating Events: `createEvents()` and Repository Selection](CQL.md#23-generating-events-createevents-and-repository-selection)
- [2.4 Filtering: Tag Filters, Field Filters, `in()`, `test()`, `cidr()`](CQL.md#24-filtering-tag-filters-field-filters-in-test-cidr)
- [2.5 Transformation: Field Assignment (`:=`), `format()`, `regex()`, `split()`, `concat()`](CQL.md#25-transformation-field-assignment-format-regex-split-concat)
- [2.6 Aggregation: `groupBy()`, `count()`, `sum()`, `avg()`, `stats()`, `collect()`, `top()`, `bucket()`, `timeChart()`](CQL.md#26-aggregation-groupby-count-sum-avg-stats-collect-top-bucket-timechart)
- [2.7 Post-Processing: `sort()`, `head()`, `tail()`, `table()`, `select()`, `rename()`, `drop()`](CQL.md#27-post-processing-sort-head-tail-table-select-rename-drop)
- [2.8 Optimal Statement Ordering](CQL.md#28-optimal-statement-ordering)
- [2.9 Common Syntax Patterns](CQL.md#29-common-syntax-patterns)
- [2.10 What's Next](CQL.md#210-whats-next)

---

## Chapter 3 — CQL Functions Reference (Classified by Role)
- [3.1 Function Classification Badges](CQL.md#31-function-classification-badges)
- [3.2 Filtering Functions](CQL.md#32-filtering-functions)
  - [3.2.1 Tag Filters (`#tag=value`)](CQL.md#321-tag-filters-tagvalue)
  - [3.2.2 Field Filters (`field=value`)](CQL.md#322-field-filters-fieldvalue)
  - [3.2.3 `in()` — Set Membership](CQL.md#323-in--set-membership)
  - [3.2.4 `test()` — Expression Evaluation](CQL.md#324-test--expression-evaluation)
  - [3.2.5 `cidr()` — IP Range Matching](CQL.md#325-cidr--ip-range-matching)
  - [3.2.6 `match()` / `regex()` — Pattern Matching](CQL.md#326-match--regex--pattern-matching)
- [3.3 Transformation Functions](CQL.md#33-transformation-functions)
  - [3.3.1 `:=` — Field Assignment](CQL.md#331--field-assignment)
  - [3.3.2 `format()` — String Formatting](CQL.md#332-format--string-formatting)
  - [3.3.3 `concat()` — String Concatenation](CQL.md#333-concat--string-concatenation)
  - [3.3.4 `split()` / `splitString()` — String Splitting](CQL.md#334-split--splitstring--string-splitting)
  - [3.3.5 `lower()` / `upper()` — Case Conversion](CQL.md#335-lower--upper--case-conversion)
  - [3.3.6 `replace()` — String Replacement](CQL.md#336-replace--string-replacement)
  - [3.3.7 `eval()` — Expression Evaluation](CQL.md#337-eval--expression-evaluation)
- [3.4 Aggregation Functions](CQL.md#34-aggregation-functions)
  - [3.4.1 `groupBy()` — Core Aggregation](CQL.md#341-groupby--core-aggregation)
  - [3.4.2 `count()` / `sum()` / `avg()` / `min()` / `max()`](CQL.md#342-count-sum-avg-min-max)
  - [3.4.3 `stats()` — Multiple Aggregations](CQL.md#343-stats--multiple-aggregations)
  - [3.4.4 `collect()` — Collect Field Values](CQL.md#344-collect--collect-field-values)
  - [3.4.5 `top()` / `rare()` — Top/Bottom Values](CQL.md#345-top-rare--topbottom-values)
  - [3.4.6 `bucket()` — Time Bucketing](CQL.md#346-bucket--time-bucketing)
  - [3.4.7 `timeChart()` — Time Series Visualization](CQL.md#347-timechart--time-series-visualization)
- [3.5 Parsing Functions](CQL.md#35-parsing-functions)
  - [3.5.1 `parseJson()`](CQL.md#351-parsejson)
  - [3.5.2 `kvParse()`](CQL.md#352-kvparse)
  - [3.5.3 `splitString()`](CQL.md#353-splitstring)
  - [3.5.4 `regex()` with Named Groups](CQL.md#354-regex-with-named-groups)
- [3.6 Enrichment Functions](CQL.md#36-enrichment-functions)
  - [3.6.1 `ipLocation()`](CQL.md#361-iplocation)
  - [3.6.2 `asn()`](CQL.md#362-asn)
  - [3.6.3 `cidr()` (enrichment)](CQL.md#363-cidr-enrichment)
  - [3.6.4 `rdns()`](CQL.md#364-rdns)
  - [3.6.5 `geoHash()`](CQL.md#365-geohash)
  - [3.6.6 `match()` — Lookup Table Enrichment](CQL.md#366-match--lookup-table-enrichment)
  - [3.6.7 `join()` — Subquery Correlation](CQL.md#367-join--subquery-correlation)
  - [3.6.8 `selfJoin()` — High-Cardinality Self-Join](CQL.md#368-selfjoin--high-cardinality-self-join)
  - [3.6.9 `readFile()` — Lookup File Access](CQL.md#369-readfile--lookup-file-access)
- [3.7 Visualization & Output Functions](CQL.md#37-visualization--output-functions)
  - [3.7.1 `table()`](CQL.md#371-table)
  - [3.7.2 `select()`](CQL.md#372-select)
  - [3.7.3 `rename()`](CQL.md#373-rename)
  - [3.7.4 `drop()`](CQL.md#374-drop)
  - [3.7.5 `sort()`](CQL.md#375-sort)
  - [3.7.6 `head()` / `tail()`](CQL.md#376-head--tail)
  - [3.7.7 `formatTime()`](CQL.md#377-formattime)
- [3.8 Quick Function Lookup Table](CQL.md#38-quick-function-lookup-table)
- [3.9 What's Next](CQL.md#39-whats-next)

---

## Chapter 4 — Threat Hunting Patterns & MITRE ATT&CK Mapping
- [4.1 Why Threat Hunting in LogScale?](CQL.md#41-why-threat-hunting-in-logscale)
- [4.2 The Golden Rule: Tag Filters First](CQL.md#42-the-golden-rule-tag-filters-first)
- [4.3 Process Execution Hunting](CQL.md#43-process-execution-hunting)
  - [4.3.1 Suspicious Process Chains](CQL.md#431-suspicious-process-chains)
  - [4.3.2 Living Off The Land Binaries (LOLBins)](CQL.md#432-living-off-the-land-binaries-lolbins)
  - [4.3.3 PowerShell Encoded Commands](CQL.md#433-powershell-encoded-commands)
  - [4.3.4 WMI & WMIC Abuse](CQL.md#434-wmi--wmic-abuse)
- [4.4 Network Hunting](CQL.md#44-network-hunting)
  - [4.4.1 Beaconing Detection](CQL.md#441-beaconing-detection)
  - [4.4.2 Suspicious DNS](CQL.md#442-suspicious-dns)
  - [4.4.3 Non-Standard Ports](CQL.md#443-non-standard-ports)
- [4.5 Authentication & Access Hunting](CQL.md#45-authentication--access-hunting)
  - [4.5.1 Brute Force / Password Spray](CQL.md#451-brute-force--password-spray)
  - [4.5.2 Impossible Travel](CQL.md#452-impossible-travel)
  - [4.5.3 Privilege Escalation](CQL.md#453-privilege-escalation)
- [4.6 Persistence Hunting](CQL.md#46-persistence-hunting)
  - [4.6.1 Scheduled Tasks](CQL.md#461-scheduled-tasks)
  - [4.6.2 Registry Run Keys](CQL.md#462-registry-run-keys)
  - [4.6.3 Service Installation](CQL.md#463-service-installation)
- [4.7 Defense Evasion Hunting](CQL.md#47-defense-evasion-hunting)
  - [4.7.1 Log Clearing](CQL.md#471-log-clearing)
  - [4.7.2 Process Injection](CQL.md#472-process-injection)
  - [4.7.3 Signed Binary Proxy Execution](CQL.md#473-signed-binary-proxy-execution)
- [4.8 Discovery & Collection Hunting](CQL.md#48-discovery--collection-hunting)
- [4.9 Command & Control Hunting](CQL.md#49-command--control-hunting)
- [4.10 Exfiltration Hunting](CQL.md#410-exfiltration-hunting)
- [4.11 MITRE ATT&CK Mapping Table](CQL.md#411-mitre-attck-mapping-table)
- [4.12 Detection Engineering Best Practices](CQL.md#412-detection-engineering-best-practices)
- [4.13 Performance-Aware Hunting](CQL.md#413-performance-aware-hunting)
- [4.14 What's Next](CQL.md#414-whats-next)

---

## Chapter 5 — Joins, Lookups & Multi-Event Correlation
- [5.1 Why Correlation in LogScale?](CQL.md#51-why-correlation-in-logscale)
- [5.2 Join Types Overview](CQL.md#52-join-types-overview)
- [5.3 `join()` — Subquery Correlation](CQL.md#53-join--subquery-correlation)
  - [5.3.1 Inner Join](CQL.md#531-inner-join)
  - [5.3.2 Left Join](CQL.md#532-left-join)
  - [5.3.3 Right Join](CQL.md#533-right-join)
  - [5.3.4 Join Performance: The 200k Row Limit](CQL.md#534-join-performance-the-200k-row-limit)
- [5.4 `selfJoin()` — High-Cardinality Self-Join](CQL.md#54-selfjoin--high-cardinality-self-join)
  - [5.4.1 `selfJoinFilter()`](CQL.md#541-selfjoinfilter)
  - [5.4.2 When to Use `selfJoin()`](CQL.md#542-when-to-use-selfjoin)
- [5.5 Ad-Hoc Tables: `defineTable()` + `match()`](CQL.md#55-ad-hoc-tables-definetable--match)
  - [5.5.1 `defineTable()` Syntax](CQL.md#551-definetable-syntax)
  - [5.5.2 `match()` Syntax](CQL.md#552-match-syntax)
  - [5.5.3 `defineTable()` vs `join()`: Decision Guide](CQL.md#553-definetable-vs-join-decision-guide)
- [5.6 Lookup Files: `readFile()` + `match()`](CQL.md#56-lookup-files-readfile--match)
  - [5.6.1 CSV Lookup Files](CQL.md#561-csv-lookup-files)
  - [5.6.2 Enrichment Patterns](CQL.md#562-enrichment-patterns)
- [5.7 Correlation Patterns](CQL.md#57-correlation-patterns)
  - [5.7.1 Process Tree (Parent-Child)](CQL.md#571-process-tree-parent-child)
  - [5.7.2 Session Reconstruction](CQL.md#572-session-reconstruction)
  - [5.7.3 Lateral Movement](CQL.md#573-lateral-movement)
- [5.8 Multi-Cluster Views](CQL.md#58-multi-cluster-views)
- [5.9 What's Next](CQL.md#59-whats-next)

---

## Chapter 6 — Dashboards, Widgets & Visualization
- [6.1 Dashboard Creation Workflow](CQL.md#61-dashboard-creation-workflow)
- [6.2 Dashboard Layout & Time Controls](CQL.md#62-dashboard-layout--time-controls)
- [6.3 Widget Types Reference](CQL.md#63-widget-types-reference)
  - [6.3.1 Time Chart](CQL.md#631-time-chart)
  - [6.3.2 Bar / Column Chart](CQL.md#632-bar--column-chart)
  - [6.3.3 Pie Chart](CQL.md#633-pie-chart)
  - [6.3.4 Table](CQL.md#634-table)
  - [6.3.5 Single Value](CQL.md#635-single-value)
  - [6.3.6 Gauge](CQL.md#636-gauge)
  - [6.3.7 Sankey](CQL.md#637-sankey)
  - [6.3.8 World Map](CQL.md#638-world-map)
  - [6.3.9 Heat Map](CQL.md#639-heat-map)
  - [6.3.10 Event List](CQL.md#6310-event-list)
  - [6.3.11 Text / Markdown](CQL.md#6311-text--markdown)
- [6.4 Widget Configuration](CQL.md#64-widget-configuration)
- [6.5 Dashboard Filters & Parameters](CQL.md#65-dashboard-filters--parameters)
- [6.6 Sharing & Scheduled Reports](CQL.md#66-sharing--scheduled-reports)
- [6.7 Export Options](CQL.md#67-export-options)
- [6.8 Dashboard Best Practices](CQL.md#68-dashboard-best-practices)
- [6.9 What's Next](CQL.md#69-whats-next)

---

## Chapter 7 — Performance, Optimization & Reference
- [7.1 How LogScale Stores Data: Segment Files](CQL.md#71-how-logscale-stores-data-segment-files)
- [7.2 Tagged Fields: The Index Advantage](CQL.md#72-tagged-fields-the-index-advantage)
- [7.3 Query Execution Model](CQL.md#73-query-execution-model)
- [7.4 Cardinality Management](CQL.md#74-cardinality-management)
  - [7.4.1 Always Use `limit=` in `groupBy()`](CQL.md#741-always-use-limit-in-groupby)
  - [7.4.2 `limit=max` Only When Necessary](CQL.md#742-limitmax-only-when-necessary)
  - [7.4.3 Filter Before Transform](CQL.md#743-filter-before-transform)
- [7.5 Statement Ordering Performance](CQL.md#75-statement-ordering-performance)
- [7.6 Time Range Optimization](CQL.md#76-time-range-optimization)
- [7.7 `join()` vs `selfJoin()` vs `defineTable()` Performance](CQL.md#77-join-vs-selfjoin-vs-definetable-performance)
- [7.8 Live vs Scheduled Query Performance](CQL.md#78-live-vs-scheduled-query-performance)
- [7.9 Query Debugging](CQL.md#79-query-debugging)
- [7.10 Optimization Checklist](CQL.md#710-optimization-checklist)
- [7.11 Reference: Decision Tables & Cheat Sheets](CQL.md#711-reference-decision-tables--cheat-sheets)
  - [7.11.1 Filter Function Decision Table](CQL.md#7111-filter-function-decision-table)
  - [7.11.2 Aggregation Function Quick Reference](CQL.md#7112-aggregation-function-quick-reference)
  - [7.11.3 Join Method Decision Guide](CQL.md#7113-join-method-decision-guide)
  - [7.11.4 CQL vs SPL Syntax Cheat Sheet](CQL.md#7114-cql-vs-spl-syntax-cheat-sheet)
  - [7.11.5 Statement Ordering Cheat Sheet](CQL.md#7115-statement-ordering-cheat-sheet)
  - [7.11.6 Common Mistakes & Anti-Patterns](CQL.md#7116-common-mistakes--anti-patterns)
  - [7.11.7 Glossary](CQL.md#7117-glossary)
  - [7.11.8 File Inventory](CQL.md#7118-file-inventory)
  - [7.11.9 Version History](CQL.md#7119-version-history)
  - [7.11.10 Contributing](CQL.md#71110-contributing)

---

## Chapter 8 — Arrays & Nested Data
- [8.1 How CQL Writes Arrays](CQL.md#81-how-cql-writes-arrays)
- [8.2 Flat vs Nested — The Distinction That Decides Everything](CQL.md#82-flat-vs-nested--the-distinction-that-decides-everything)
- [8.3 Filtering Events by Array Content](CQL.md#83-filtering-events-by-array-content)
  - [8.3.1 `array:contains()` — Exact Value Match](CQL.md#831-arraycontains--exact-value-match)
  - [8.3.2 `array:exists()` — Condition Match](CQL.md#832-arrayexists--condition-match)
  - [8.3.3 `array:filter()` — Transform Elements](CQL.md#833-arrayfilter--transform-elements)
- [8.4 Array Utilities](CQL.md#84-array-utilities)
  - [8.4.1 `array:dedup()` — Remove Duplicates](CQL.md#841-arraydedup--remove-duplicates)
  - [8.4.2 `array:append()` — Add Elements](CQL.md#842-arrayappend--add-elements)
- [8.5 Calculating Over Arrays](CQL.md#85-calculating-over-arrays)
  - [8.5.1 `array:length()` — Count Elements](CQL.md#851-arraylength--count-elements)
  - [8.5.2 The `reduce` Family — Aggregate Arrays](CQL.md#852-the-reduce-family--aggregate-arrays)
- [8.6 Nested Arrays: objectArray:* Functions](CQL.md#86-nested-arrays-objectarray-functions)
  - [8.6.1 `objectArray:eval()` — The Bridge to Flat](CQL.md#861-objectarrayeval--the-bridge-to-flat)
  - [8.6.2 `objectArray:exists()` — Filter by Nested Content](CQL.md#862-objectarrayexists--filter-by-nested-content)
- [8.7 Real SOC Example — Hunting in DNS Arrays](CQL.md#87-real-soc-example--hunting-in-dns-arrays)
- [8.8 KQL Comparison](CQL.md#88-kql-comparison)
- [8.9 Common Mistakes](CQL.md#89-common-mistakes)

---

## Chapter 9 — Correlating Events (Joins, Self-Joins, Lookups)
- [9.1 The Correlation Problem](CQL.md#91-the-correlation-problem)
- [9.2 Method Comparison](CQL.md#92-method-comparison)
- [9.3 `join()` — Subquery Correlation](CQL.md#93-join--subquery-correlation)
  - [9.3.1 Inner Join](CQL.md#931-inner-join)
  - [9.3.2 Left Join](CQL.md#932-left-join)
  - [9.3.3 Right Join](CQL.md#933-right-join)
  - [9.3.4 The 200k Row Hard Limit](CQL.md#934-the-200k-row-hard-limit)
- [9.4 `selfJoin()` / `selfJoinFilter()` — High-Cardinality Self-Join](CQL.md#94-selfjoin--selfjoinfilter--high-cardinality-self-join)
  - [9.4.1 `selfJoinFilter()` — Parent-Child Process Correlation](CQL.md#941-selfjoinfilter--parent-child-process-correlation)
  - [9.4.2 When to Use `selfJoin()`](CQL.md#942-when-to-use-selfjoin)
- [9.5 Ad-Hoc Tables: `defineTable()` + `match()`](CQL.md#95-ad-hoc-tables-definetable--match)
  - [9.5.1 `defineTable()` Syntax](CQL.md#951-definetable-syntax)
  - [9.5.2 `match()` Syntax](CQL.md#952-match-syntax)
  - [9.5.3 Decision Guide: `defineTable()` vs `join()`](CQL.md#953-decision-guide-definetable-vs-join)
- [9.6 Lookup Files: `readFile()` + `match()`](CQL.md#96-lookup-files-readfile--match)
  - [9.6.1 CSV Lookup Files](CQL.md#961-csv-lookup-files)
  - [9.6.2 Enrichment Patterns](CQL.md#962-enrichment-patterns)
- [9.7 Correlation Patterns](CQL.md#97-correlation-patterns)
  - [9.7.1 Process Tree (Parent-Child)](CQL.md#971-process-tree-parent-child)
  - [9.7.2 Session Reconstruction](CQL.md#972-session-reconstruction)
  - [9.7.3 Lateral Movement](CQL.md#973-lateral-movement)
- [9.8 Multi-Cluster Views](CQL.md#98-multi-cluster-views)
- [9.9 KQL Comparison](CQL.md#99-kql-comparison)
- [9.10 Common Mistakes](CQL.md#910-common-mistakes)

---

## Labs (Hands-On Practice)
- [Lab Data](labs/data/README.md) — Synthetic dataset schema and import instructions
- [Lab 01: Syntax Fundamentals](labs/01-syntax-fundamentals/README.md) — CQL vs SPL, field assignment, filtering
- [Lab 02: Function Practice](labs/02-function-practice/README.md) — groupBy, timeChart, ipLocation, match
- [Lab 03: Threat Hunting](labs/03-threat-hunting/README.md) — Brute force, beaconing, process chains
- [Lab 04: Dashboards](labs/04-dashboards/README.md) — Widget creation, parameters, sharing
- [Lab 05: Arrays & JSON](labs/05-arrays-json/README.md) — array:contains, array:filter, objectArray:eval
- [Lab 06: Correlation](labs/06-correlation/README.md) — join, selfJoin, defineTable, match

---

## Reference Files
- [SOURCES.md](SOURCES.md) — Official LogScale docs, CrowdStrike community, GitHub references
- [CQL.md](CQL.md) — Complete single-file reference
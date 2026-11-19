# CrowdStrike Query Language (CQL) — Complete Reference (v1.0)

> **Research baseline**: 19 November 2026 | **Products**: Falcon LogScale Cloud / Self-Hosted (latest)

---

## Quick Navigation

- [Why This Reference Exists](#why-this-reference-exists)
- [Chapter 1: Foundations — Events, Repositories, Tagged Fields & Data Model](#chapter-1--foundations-events-repositories-tagged-fields--data-model)
- [Chapter 2: Query Syntax Fundamentals & Statement Ordering](#chapter-2--query-syntax-fundamentals--statement-ordering)
- [Chapter 3: CQL Functions Reference (Classified by Role)](#chapter-3--cql-functions-reference-classified-by-role)
- [Chapter 4: Threat Hunting Patterns & MITRE ATT&CK Mapping](#chapter-4--threat-hunting-patterns--mitre-attck-mapping)
- [Chapter 5: Joins, Lookups & Multi-Event Correlation](#chapter-5--joins-lookups--multi-event-correlation)
- [Chapter 6: Dashboards, Widgets & Visualization](#chapter-6--dashboards-widgets--visualization)
- [Chapter 7: Performance, Optimization & Reference](#chapter-7--performance-optimization--reference)
- [Labs (Hands-On Practice)](#labs-hands-on-practice)
- [Evidence Standard](#evidence-standard)

---

## Why This Reference Exists

Most LogScale resources teach functions in isolation. This reference teaches **decision-making**: when to use each function, why alternatives exist, and how they behave differently in live queries vs scheduled searches vs dashboards.

**Target audience**: SOC analysts, threat hunters, detection engineers, and LogScale architects working with CrowdStrike Falcon LogScale.

### Structure

| Part | Topic | Purpose |
|------|-------|---------|
| Ch 1 | Foundations | Events, repositories, tagged fields, parsers, data model |
| Ch 2 | Syntax Fundamentals | Pipeline model, CQL vs SPL, optimal statement ordering |
| Ch 3 | Functions Reference | Every function classified by role (filter/transform/aggregate/parse/enrich/visualize) |
| Ch 4 | Threat Hunting | MITRE ATT&CK mapped patterns, real detection logic |
| Ch 5 | Joins & Lookups | join, selfJoin, defineTable+match, readFile — when to use each |
| Ch 6 | Dashboards | Widget types, configuration, parameters, sharing |
| Ch 7 | Performance | Segment files, cardinality, join limits, optimization checklist |

### Key Features

| Feature | Description |
|---------|-------------|
| **Function Classification** | Every function tagged: filtering, transformation, aggregation, parsing, enrichment, visualization |
| **CQL vs SPL Mapping** | Side-by-side syntax with semantic differences explained |
| **Statement Ordering** | Tag filters → field filters → transforms → aggregations → post-processing |
| **Threat Hunting Patterns** | Real detection logic: brute force, beaconing, process chains, lateral movement |
| **Join Decision Guide** | join vs selfJoin vs defineTable+match with 200k row limit awareness |
| **Performance Mindset** | Tagged fields (indexed), cardinality management, filter-before-transform |

---

## Evidence Standard (Required for All Examples)

Every substantial example in this reference follows this standard:

| Requirement | Description |
|-------------|-------------|
| **Product & Version** | Falcon LogScale Cloud / Self-Hosted (version) |
| **Input Example** | Small synthetic event showing relevant fields (via `createEvents()`) |
| **Exact Query** | Copy-pasteable CQL |
| **Expected Output** | Table or description of result |
| **Why This Function** | Explanation of classification & intent |
| **Performance Note** | Tag filter usage, cardinality impact, join limits |
| **Official LogScale Reference** | Link to current docs |

**Official documentation is the authority.** Community examples and GitHub repositories are useful for learning patterns and troubleshooting, but must not override current product documentation.

---

# Chapter 1 — Foundations: Events, Repositories, Tagged Fields & Data Model

> **Research baseline**: 19 November 2026 | **Products**: Falcon LogScale Cloud / Self-Hosted

---

## 1.1 Why This Chapter Exists

Before writing **CQL** queries, you must understand **what you are querying**. Most beginners start with syntax:

```cql
// CQL
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
| groupBy([ComputerName], function=count())
```

They learn syntax but don't understand where `#event_simpleName`, `ImageFileName`, `ComputerName`, `@timestamp`, `@rawstring` come from. That becomes a problem when working with:
- Parsers (index-time field extraction)
- Tagged fields (the performance key)
- Repositories vs Views
- Ingestion-time vs search-time processing
- CrowdStrike Parsing Standard (CPS)

**This chapter gives you the vocabulary for everything that follows.**

---

## 1.2 What Is a LogScale Event?

An **event** is a single record representing something that happened at a point in time.

```
┌─────────────────────────────────────────────────────────────┐
│  One LogScale Event                                         │
├─────────────────────────────────────────────────────────────┤
│  @timestamp = 2026-09-23T10:15:22.123Z                     │
│  @rawstring = Sep 23 10:15:22 DC01 user=admin              │
│              EventCode=4625 LogonType=3                    │
│  @id        = 550e8400-e29b-41d4-a716-446655440000         │
│  #repo      = windows                                       │
│  #type      = ProcessRollup2                                │
│  host       = DC01                                          │
│  source     = WinEventLog:Security                         │
│  ImageFileName = C:\Windows\System32\powershell.exe        │
│  CommandLine  = powershell -enc <base64>                   │
│  ComputerName = WORKSTATION01                              │
└─────────────────────────────────────────────────────────────┘
```

**Key insight**: An event is not a "row" in a database. It's a semi-structured blob (`@rawstring`) with metadata fields attached. LogScale stores events in **segment files** (compressed, columnar) optimized for time-series queries.

---

## 1.3 Where Do Events Come From?

```
Data Source              →  Collector/Forwarder  →  LogScale  →  Repository
━━━━━━━━━━━━━━━━━━━━━━━━━   ━━━━━━━━━━━━━━━━━━━━   ━━━━━━━━━━   ━━━━━━━━━━━
Windows Event Logs        Falcon Sensor              │       windows
Linux /var/log            Falcon Sensor              │       linux
Firewall syslog           LogScale Collector         │       firewall
Cloud APIs (AWS/Azure/GCP) LogScale Collector        │       cloud
Custom logs               LogScale Collector / HEC   │       custom
Kubernetes audit          Falcon Sensor              │       kubernetes
```

**Critical path**: Data → **Parser** (index-time) → Segment Files → Search (search-time)

---

## 1.4 What Is a Repository?

A **repository** is a physical storage container for events — like a database partition with its own retention, access control, and storage.

```cql
// Query a specific repository (in UI, select repo from dropdown)
// In API: specify repository name in request
```

Repositories control:
- Data retention (time and/or size)
- Access permissions (RBAC)
- Storage tier (hot/warm/cold)
- Parser assignment

**Best practice**: Separate repositories by data domain (windows, linux, firewall, cloud) and/or team.

---

## 1.5 Views: Curated Subsets of Repositories

A **view** is a logical subset of one or more repositories with optional field filtering and field renaming.

```
Repository: windows (all Windows events)
    │
    ├── View: windows-process (only #event_simpleName=ProcessRollup2*)
    ├── View: windows-auth (only #event_simpleName=UserLogon*)
    └── View: windows-network (only #event_simpleName=NetworkConnect*)
```

Views provide:
- **Data isolation** without duplicating storage
- **Field renaming** for consistent schemas across repos
- **Default time ranges** and **default queries**
- **Access control** at view level

```cql
// Query a view (same syntax, just select view in UI or API)
// In CQL, you don't specify repo/view in the query — it's a UI/API context
```

---

## 1.6 Tagged Fields (`#tag`): The Performance Key

**Tagged fields** are fields indexed at ingestion time. They are prefixed with `#` and are the **fastest way to filter** in LogScale.

| Tagged Field | Purpose | Example Values |
|--------------|---------|----------------|
| `#repo` | Repository name | `windows`, `linux`, `firewall` |
| `#type` | Event type / parser output | `ProcessRollup2`, `UserLogon`, `NetworkConnectIP4` |
| `#event_simpleName` | Simplified event type | `ProcessRollup2`, `DnsRequest`, `FileWrite` |

**Why they matter**: Tagged fields use **bloom filters** and **segment-level indexing**. Filtering on `#type=ProcessRollup2` scans only relevant segments — orders of magnitude faster than filtering on non-tagged fields.

```cql
// FAST: Tag filter (uses index)
#event_simpleName=ProcessRollup2

// SLOW: Non-tagged field filter (full scan)
ImageFileName="powershell.exe"

// CORRECT ORDER: Tag first, then field
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
```

**Official reference**: [Tagged Fields](https://library.humio.com/data-management/tagged-fields.html)

---

## 1.7 Internal Fields (`@*` prefix)

Fields prefixed with `@` are LogScale-internal. They exist on every event.

| Field | Meaning | Use Case |
|-------|---------|----------|
| `@timestamp` | Event timestamp (ISO 8601, UTC) | Time-range filtering, `bucket()`, `timeChart()` |
| `@rawstring` | Original unparsed event text | Regex extraction, `kvParse()`, debugging |
| `@id` | Unique event UUID | Deduplication, exact event lookup |
| `@ingesttimestamp` | When LogScale ingested the event | Ingestion latency: `eval lag=@ingesttimestamp-@timestamp` |

> **`@rawstring` is the source of truth.** All search-time extractions derive from it.

---

## 1.8 Default Fields (Common Across Event Types)

These fields are commonly present depending on the parser and event source.

| Field | Description | Example |
|-------|-------------|---------|
| `#repo` | Repository name (tagged) | `windows` |
| `#type` | Event type / parser name (tagged) | `ProcessRollup2` |
| `host` | Originating hostname | `DC01`, `web-01` |
| `source` | Input source | `WinEventLog:Security`, `/var/log/secure` |
| `ComputerName` | Source computer (CPS standard) | `WORKSTATION01` |
| `aid` | Agent ID (CrowdStrike sensor) | `550e8400-e29b-41d4-a716-446655440000` |

**Search usage:**
```cql
// Tag filters (fastest)
#repo=windows #event_simpleName=ProcessRollup2

// Field filters (after tag filters)
| host="DC01"
| ComputerName="WORKSTATION01"
```

---

## 1.9 Field Categories Summary Table

```
┌────────────────────────────────────────────────────────────────────┐
│                    FIELD ORIGIN TAXONOMY                           │
├──────────────────┬────────────────────┬───────────────────────────┤
│ Category         │ Examples           │ When Available            │
├──────────────────┼────────────────────┼───────────────────────────┤
│ Internal         │ @timestamp,        │ Always                    │
│                  │ @rawstring, @id    │                           │
├──────────────────┼────────────────────┼───────────────────────────┤
│ Tagged (indexed) │ #repo, #type,      │ At ingestion (parser)     │
│                  │ #event_simpleName  │                           │
├──────────────────┼────────────────────┼───────────────────────────┤
│ CPS Standard     │ host, source,      │ At ingestion (CPS parser) │
│ (indexed/search) │ ComputerName, aid  │                           │
├──────────────────┼────────────────────┼───────────────────────────┤
│ Parser-Extracted │ ImageFileName,     │ At ingestion (parser)     │
│                  │ CommandLine,       │                           │
│                  │ User, ProcessId    │                           │
├──────────────────┼────────────────────┼───────────────────────────┤
│ Search-Time      │ fileName :=        │ At query time (CQL)       │
│ (calculated)     │ lower(ImageFileName)│                          │
└──────────────────┴────────────────────┴───────────────────────────┘
```

---

## 1.10 Ingestion-Time vs Search-Time Processing

**Most important architectural distinction in LogScale.**

### Search-Time Processing (What you do in CQL)
```cql
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
| groupBy([ComputerName], function=count())
```
- Runs on **already-indexed** data
- Does **not** modify stored events
- Results exist only for this query

### Ingestion-Time Processing (Parsers)
```
Raw Data → [Parser: regex, kvParse, JSON, CPS] → Structured Event → Segment File
```
- Modifies **what gets stored**
- Affects **all future queries**
- Configured in **Parser** (YAML/JSON in UI or API)

### CrowdStrike Parsing Standard (CPS 1.2)
The schema standard for normalizing fields across data sources.
- **Mandatory fields**: `@timestamp`, `#type`, `host`, `source`
- **Standardized field names**: `ImageFileName` (not `Image` or `process_name`), `CommandLine`, `User`, `ProcessId`, `ParentProcessId`, etc.
- **Tagged fields**: `#event_simpleName` for high-level categorization

**Official reference**: [CrowdStrike Parsing Standard 1.2](https://library.humio.com/data-management/crowdstrike-parsing-standard.html)

---

## 1.11 Parsers: Structure at Ingest

A **parser** transforms raw log lines into structured events at ingestion time.

```yaml
# Example parser (YAML)
name: "windows-security"
tagFields:
  - "#event_simpleName"
parse:
  - regex: "<(?<EventCode>\\d+)>.*User=(?<User>\\w+)"
    field: "@rawstring"
  - kvParse:
      field: "@rawstring"
```

Parser capabilities:
- **Regex extraction** with named groups
- **Key-value parsing** (`kvParse`)
- **JSON parsing** (`parseJson`)
- **Field assignment** and **renaming**
- **Tag assignment** (`#event_simpleName`)
- **Field dropping** (reduce storage)

**Best practice**: Use CPS-compliant parsers. Write custom parsers only for non-standard logs.

**Official reference**: [Parsing Data](https://library.humio.com/data-management/parse-data.html)

---

## 1.12 Filtering, Routing, Enrichment: Three Different Problems

| Problem | Question | Search-Time (CQL) | Ingestion-Time (Parser) |
|---------|----------|-------------------|-------------------------|
| **Filtering** | Should this event be queried? | `#type=ProcessRollup2 \| ImageFileName="powershell.exe"` | Parser `dropEvent()` — event never stored |
| **Routing** | Which repository/view? | N/A (query context) | Parser `repo := "windows"` or parser per repo |
| **Enrichment** | Add context to event? | `ipLocation()`, `asn()`, `match()` lookup | Parser enrichment (GeoIP, ASN at ingest) |

**Why this matters**: Beginners confuse these.
- "Drop debug logs" → Ingestion-time parser `dropEvent()` (saves license, storage)
- "Hide passwords in dashboards" → Search-time `drop()` or field-level masking
- "Windows logs in one repo, Linux in another" → Ingestion-time routing (parser per repo or `repo` assignment)

---

## 1.13 Key Takeaways

1. **Events = `@rawstring` + metadata fields**. `@rawstring` is immutable at search time.
2. **Tagged fields (`#tag`) are indexed** — use them **first** for performance.
3. **Repositories = physical storage**. Views = logical subsets. Parsers = structure at ingest.
4. **CPS standardizes field names** — learn the canonical names (`ImageFileName`, `CommandLine`, `User`, `ProcessId`).
5. **Ingestion-time = write path (parsers)**. Search-time = read path (CQL). Different tools.
6. **Filtering ≠ Routing ≠ Enrichment**. Know which problem you're solving.

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 2 — Query Syntax Fundamentals & Statement Ordering

---

## 2.1 The Pipeline Model

Every CQL query is a **pipeline** — functions connected by `|` (pipe).

```
INPUT EVENTS → [FUNCTION 1] → [FUNCTION 2] → [FUNCTION 3] → OUTPUT RESULTS
                    │              │              │
                    ▼              ▼              ▼
               filtering      transformation   aggregation
```

```cql
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
| fileName := lower(ImageFileName)
| groupBy([ComputerName], function=count())
| sort(_count, order=desc)
| head(10)
```

Flow:
1. `#event_simpleName=ProcessRollup2` → Tag filter (generates event stream from index)
2. `| ImageFileName="powershell.exe"` → Field filter (filters stream)
3. `| fileName := lower(ImageFileName)` → Transformation (creates new field)
4. `| groupBy([ComputerName], function=count())` → Aggregation (transforms to summary)
5. `| sort(_count, order=desc)` → Post-processing (reorders rows)
6. `| head(10)` → Post-processing (limits rows)

---

## 2.2 CQL vs SPL: Critical Syntax Differences

**LogScale CQL is NOT Splunk SPL. Never mix syntax between these languages.**

| Operation | LogScale CQL | NOT Splunk SPL |
|-----------|--------------|----------------|
| **Field assignment** | `newField := value` | `eval newField=value` |
| **String concatenation** | `field1 + " " + field2` or `concat(field1, " ", field2)` | `field1." ".field2` |
| **Rename fields** | `rename(old, as=new)` | `rename old AS new` |
| **Aggregation** | `groupBy(field, function=count())` | `stats count by field` |
| **Time bucketing** | `bucket(span=1h, function=count())` | `bin span=1h \| stats count` |
| **Time series chart** | `timeChart(span=1h, function=count())` | `timechart span=1h count` |
| **Tagged field filter** | `#event_simpleName=ProcessRollup2` | No direct equivalent |
| **Field filter** | `ImageFileName="powershell.exe"` | `ImageFileName="powershell.exe"` |
| **Set membership** | `in(field, values=[a,b,c])` | `field IN (a,b,c)` |
| **Regex match (filter)** | `field=/pattern/i` or `match(field, "pattern")` | `regex field="pattern"` |
| **Field extraction (regex)** | `regex("pattern", field=@rawstring)` | `rex field=_raw "pattern"` |
| **Wildcard in filter** | `field="prefix*"` (prefix only) | `field="prefix*"` (glob) |
| **SQL-like pattern** | `field LIKE "prefix%"` (in `test()`) | `field LIKE "prefix%"` |
| **Boolean AND** | Implicit between filters | `AND` explicit in `where` |
| **Boolean OR** | `in(field, values=[a,b])` or `test()` | `OR` explicit in `where` |
| **Negation (field exists)** | `field=*` | `field=*` |
| **Negation (field not value)** | `field!="value"` | `field!="value"` |
| **Negation (field not value OR missing)** | `not(field="value")` | `NOT field="value"` |

### CQL Does Not Have
- `search` command (use tag/field filters directly)
- `where` command (use `test()` or filter syntax)
- `eval` command (use `:=` assignment)
- `stats` command (use `groupBy()` or `stats()`)
- `table` command (use `table()` or `select()`)
- `sort` command (use `sort()` function)
- `head`/`tail` commands (use `head()`/`tail()` functions)
- `join` command (use `join()` function — different semantics)
- `lookup` command (use `match()` + `readFile()` or `defineTable()`)

---

## 2.3 Generating Events: `createEvents()` and Repository Selection

### Repository Selection
In the LogScale UI, you select the repository/view from the dropdown. In API, you specify it in the request. **There is no `FROM` or `search` command in CQL.**

```cql
// In UI: Select repository "windows" from dropdown
// Then run:
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
```

### `createEvents()` — Synthetic Events for Testing
```cql
// Create synthetic events for testing
createEvents([
  "@timestamp=2026-09-23T10:15:22Z, #event_simpleName=ProcessRollup2, ImageFileName=powershell.exe, CommandLine=powershell -enc ABC, ComputerName=WKS01",
  "@timestamp=2026-09-23T10:16:00Z, #event_simpleName=ProcessRollup2, ImageFileName=cmd.exe, CommandLine=cmd /c whoami, ComputerName=WKS01"
])
| kvParse()
| groupBy([ComputerName], function=count())
```

**Use case**: Testing queries, building lookup tables, creating sample data for dashboards.

---

## 2.4 Filtering: Tag Filters, Field Filters, `in()`, `test()`, `cidr()`

### Tag Filters (Fastest — Always First)
```cql
// Single tag
#event_simpleName=ProcessRollup2

// Multiple tags (implicit AND)
#repo=windows #event_simpleName=ProcessRollup2

// Tag with wildcard (prefix only)
#event_simpleName=Process*
```

### Field Filters (Exact Match, Prefix Wildcard)
```cql
// Exact match
ImageFileName="powershell.exe"

// Prefix wildcard (suffix only)
ImageFileName="powershell*"

// Multiple field filters (implicit AND)
ImageFileName="powershell.exe"
| ComputerName="WKS01"
```

### `in()` — Set Membership
```cql
// Single field, multiple values (OR logic)
ImageFileName=in(["powershell.exe", "pwsh.exe", "powershell_ise.exe"])

// Multiple fields (each field matches any value)
in(field=[ImageFileName, CommandLine], values=["powershell*", "cmd.exe"])

// Case-insensitive
in(field=ImageFileName, values=["powershell.exe"], ignoreCase=true)
```

### `test()` — Expression Evaluation
```cql
// Field-to-field comparison
test(bytes_out > bytes_in)

// Arithmetic
test(bytes_total > 100000)

// Complex boolean
test((action="failure" AND attempts>5) OR (user="admin" AND not(cidr(src_ip, "10.0.0.0/8"))))

// String functions
test(lower(ImageFileName)="powershell.exe")
test(match(CommandLine, "(?i)encodedcommand"))

// LIKE pattern (SQL-style)
test(ImageFileName LIKE "power%")
test(host LIKE "DC0_")  // _ = single char
```

### `cidr()` — IP Range Matching
```cql
// Filter private IPs
cidr(src_ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

// Negate: public IPs only
not(cidr(src_ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]))
```

---

## 2.5 Transformation: Field Assignment (`:=`), `format()`, `regex()`, `split()`, `concat()`

### `:=` — Field Assignment (Core Transformation)
```cql
// Simple assignment
fileName := lower(ImageFileName)

// Expression
bytes_total := bytes_in + bytes_out

// Conditional (if/then/else)
severity_level := if(severity=3, then="error", else="info")

// Function result
timestamp_formatted := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp)
```

### `format()` — String Formatting (printf-style)
```cql
// Basic formatting
event_summary := format("%s on %s: %s", field=[ImageFileName, ComputerName, CommandLine])

// With numbers
bytes_display := format("%,.2f MB", field=[bytes_total/1024/1024])

// Padding
padded := format("%05d", field=[count])
```

### `concat()` — String Concatenation
```cql
// Two fields
full_path := concat(Directory, "\\", FileName)

// Multiple fields with separator
cmdline := concat([ImageFileName, " ", CommandLine])

// Equivalent: field1 + " " + field2
```

### `split()` / `splitString()` — String Splitting
```cql
// Split by delimiter into array
tld_parts := splitString(field=DomainName, by=".")

// Get last element (TLD)
tld := getArrayElement(array=tld_parts, index=-1)
```

### `regex()` — Field Extraction with Named Groups
```cql
// Extract from @rawstring
regex("(?<user>\\w+)\\s+logon", field=@rawstring)

// Extract from specific field
regex("(?<domain>[^.]+)\\.(?<tld>[^.]+)$", field=DomainName)

// Multiple named groups
regex("(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+):(?<port>\\d+)", field=NetworkAddress)
```

### `replace()` — String Replacement
```cql
// Simple replace
clean_cmd := replace(field=CommandLine, with="", regex="(?i)-enc\\s+\\w+")

// Mask sensitive data
masked := replace(field=CommandLine, with="***REDACTED***", regex="(?i)password=\\S+")
```

### `lower()` / `upper()` — Case Conversion
```cql
file_lower := lower(ImageFileName)
domain_upper := upper(DomainName)
```

---

## 2.6 Aggregation: `groupBy()`, `count()`, `sum()`, `avg()`, `stats()`, `collect()`, `top()`, `bucket()`, `timeChart()`

### `groupBy()` — Core Aggregation
```cql
// Single field, count
#event_simpleName=ProcessRollup2
| groupBy([ComputerName], function=count())

// Multiple fields
| groupBy([ComputerName, ImageFileName], function=count())

// With limit (CRITICAL for performance)
| groupBy([ComputerName], function=count(), limit=10000)

// Multiple aggregations
| groupBy(
    [ComputerName],
    function=[
      count(as=event_count),
      sum(field=bytes_total, as=total_bytes),
      avg(field=bytes_total, as=avg_bytes),
      collect(field=ImageFileName, as=processes)
    ]
)
```

### `count()` / `sum()` / `avg()` / `min()` / `max()` — Aggregation Functions
```cql
// Used inside groupBy() function parameter
groupBy([host], function=[count(), sum(bytes), avg(bytes), min(@timestamp), max(@timestamp)])
```

### `stats()` — Multiple Aggregations (Alternative to groupBy)
```cql
// stats() is similar to groupBy but with different syntax
stats(
  count(as=total),
  sum(bytes, as=total_bytes),
  avg(bytes, as=avg_bytes),
  by=[host, sourcetype]
)
```

### `collect()` — Collect Field Values
```cql
// Collect all values (use limit!)
groupBy([ComputerName], function=collect(ImageFileName, limit=1000))

// Collect multiple fields
groupBy([ComputerName], function=collect([ImageFileName, CommandLine, ProcessId], limit=1000))
```

### `top()` / `rare()` — Top/Bottom Values
```cql
// Top 10 processes by count
groupBy([ImageFileName], function=count())
| top(10, field=_count)

// Rare values
groupBy([User], function=count())
| rare(5, field=_count)
```

### `bucket()` — Time Bucketing
```cql
// Time buckets with aggregation
#event_simpleName=ProcessRollup2
| bucket(span=1h, function=count())

// Multiple aggregations per bucket
| bucket(
  span=1h,
  function=[
    count(),
    collect(ImageFileName, limit=100)
  ]
)
```

### `timeChart()` — Time Series Visualization
```cql
// Time chart (optimized for dashboards)
#event_simpleName=ProcessRollup2
| timeChart(span=1h, function=count())

// By field
| timeChart(span=1h, function=count(), series=ImageFileName)

// Multiple series
| timeChart(span=1h, function=[count(), sum(bytes)], series=action)
```

---

## 2.7 Post-Processing: `sort()`, `head()`, `tail()`, `table()`, `select()`, `rename()`, `drop()`

### `sort()` — Sort Results
```cql
// Descending (default for numbers)
sort(_count, order=desc)

// Ascending
sort(@timestamp, order=asc)

// Multiple fields
sort([ComputerName, _count], order=[asc, desc])
```

### `head()` / `tail()` — Limit Results
```cql
// First N rows
head(10)

// Last N rows
tail(10)
```

### `table()` — Tabular Output (Aggregation)
```cql
// Table with specific fields (limits to 200 rows by default)
table([ComputerName, ImageFileName, _count], limit=1000)

// table() is an AGGREGATION — reduces rows
```

### `select()` — Pluck Fields (No Aggregation)
```cql
// Select fields without reducing rows (keeps all events)
select([@timestamp, ComputerName, ImageFileName, CommandLine])

// Use select() when you want to keep event granularity
// Use table() when you want aggregated summary
```

### `rename()` — Rename Fields
```cql
// Single rename
rename(field=ImageFileName, as=ProcessName)

// Multiple renames
rename(field=[ImageFileName, ComputerName], as=[ProcessName, Host])
```

### `drop()` — Remove Fields
```cql
// Drop single field
drop(@rawstring)

// Drop multiple fields
drop([@id, @ingesttimestamp, _count])
```

---

## 2.8 Optimal Statement Ordering

**Golden Rule**: Filter early (reduce cardinality), transform middle, aggregate late, post-process last.

```
┌─────────────────────────────────────────────────────────────────────┐
│                    OPTIMAL QUERY STRUCTURE                          │
├─────────────────────────────────────────────────────────────────────┤
│  1. TAG FILTERS (most selective, indexed)                          │
│     #event_simpleName=ProcessRollup2                               │
│     #repo=windows                                                  │
│                                                                     │
│  2. FIELD FILTERS (exact matches before wildcards)                 │
│     | ImageFileName="powershell.exe"                               │
│     | ComputerName="WKS01"                                         │
│                                                                     │
│  3. COMPLEX FILTERS (in, test, cidr, regex)                        │
│     | in(field=User, values=["admin", "administrator"])            │
│     | test(match(CommandLine, "(?i)encodedcommand"))               │
│     | not(cidr(src_ip, subnet=["10.0.0.0/8"]))                     │
│                                                                     │
│  4. TRANSFORMATIONS (field assignment, formatting)                 │
│     | fileName := lower(ImageFileName)                             │
│     | timestamp := formatTime("%Y-%m-%d", field=@timestamp)       │
│                                                                     │
│  5. AGGREGATIONS (groupBy, timeChart, bucket, stats)               │
│     | groupBy([ComputerName], function=count(), limit=10000)       │
│                                                                     │
│  6. POST-PROCESSING (sort, head, table, select, rename, drop)      │
│     | sort(_count, order=desc)                                     │
│     | head(10)                                                     │
│     | table([ComputerName, _count])                                │
└─────────────────────────────────────────────────────────────────────┘
```

### Why Order Matters

| Wrong Order | Problem | Correct Order |
|-------------|---------|---------------|
| `groupBy` → `filter` | Aggregates all data, then filters | Filter → `groupBy` |
| `sort` → `filter` | Sorts full dataset, then filters | Filter → `sort` |
| `field=*` → `#tag` | Full scan, then tag filter | `#tag` → `field=*` |
| `timeChart` → `filter` | Charts all time, then filters | Filter → `timeChart` |

---

## 2.9 Common Syntax Patterns

### Pattern: Process Execution with Enrichment
```cql
#event_simpleName=ProcessRollup2
| ImageFileName=in(["powershell.exe", "pwsh.exe", "cmd.exe"])
| test(match(CommandLine, "(?i)(encodedcommand|bypass|hidden)"))
| fileName := lower(ImageFileName)
| ipLocation(OriginSourceIpAddress, as=geo)
| asn(OriginSourceIpAddress, as=asn_info)
| groupBy([ComputerName, fileName], function=[count(), collect([CommandLine, geo.country, asn_info.org])])
| sort(_count, order=desc)
```

### Pattern: Network Connection Analysis
```cql
#event_simpleName=NetworkConnectIP4
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]))
| RemotePort=in([443, 80, 8080, 8443, 22, 3389, 445, 135, 139])
| ipLocation(RemoteAddressIP4, as=geo)
| asn(RemoteAddressIP4, as=asn)
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[count(), collect([geo.country, asn.org, ProcessName])])
| sort(_count, order=desc)
```

### Pattern: Authentication Failure Analysis
```cql
#event_simpleName=UserLogonFailed
| groupBy([ComputerName, User, SourceIp], function=count())
| test(_count > 10)
| ipLocation(SourceIp, as=geo)
| groupBy([User], function=[sum(_count, as=total_failures), collect([ComputerName, SourceIp, geo.country])])
| sort(total_failures, order=desc)
```

---

## 2.10 What's Next

- **Chapter 3**: Complete function reference classified by role
- **Chapter 4**: Threat hunting patterns mapped to MITRE ATT&CK
- **Chapter 5**: Joins, lookups, and multi-event correlation
- **Chapter 6**: Dashboards and visualization
- **Chapter 7**: Performance optimization and reference tables

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 3 — CQL Functions Reference (Classified by Role)

---

## 3.1 Function Classification Badges

Throughout this reference, functions are tagged with their primary role:

| Badge | Role | Description |
|-------|------|-------------|
| 🔍 | **Filtering** | Reduce event stream early (tag filters, field filters, `in`, `test`, `cidr`) |
| 🔄 | **Transformation** | Create/modify fields (`:=`, `format`, `concat`, `split`, `lower`, `replace`, `eval`) |
| 📊 | **Aggregation** | Summarize events (`groupBy`, `count`, `sum`, `stats`, `collect`, `top`, `bucket`, `timeChart`) |
| 📝 | **Parsing** | Extract structure (`parseJson`, `kvParse`, `splitString`, `regex` with named groups) |
| 🌐 | **Enrichment** | Add external context (`ipLocation`, `asn`, `cidr`, `rdns`, `geoHash`, `match`, `join`, `readFile`) |
| 📈 | **Visualization** | Shape output (`table`, `select`, `rename`, `drop`, `sort`, `head`, `tail`, `formatTime`) |

**Functions can have multiple roles** depending on usage. E.g., `regex()` is 📝 Parsing when extracting fields, 🔍 Filtering when used in `test()`.

---

## 3.2 Filtering Functions 🔍

### 3.2.1 Tag Filters (`#tag=value`) 🔍
```cql
#event_simpleName=ProcessRollup2
#repo=windows
#type=ProcessRollup2
```
- **Indexed**: Uses bloom filters + segment indexes
- **Fastest filter type**: Always use first
- **Prefix wildcard only**: `#event_simpleName=Process*`

**Official ref**: [Tagged Fields](https://library.humio.com/data-management/tagged-fields.html)

### 3.2.2 Field Filters (`field=value`) 🔍
```cql
ImageFileName="powershell.exe"
ComputerName="WKS01"
User="admin"
```
- **Exact match** or **prefix wildcard** (`field="prefix*"`)
- **Implicit AND** between multiple filters
- **After tag filters** in pipeline

### 3.2.3 `in()` — Set Membership 🔍
```cql
// Syntax: in(field=<field>, values=[<array>], ignoreCase=<bool>)

// Single field
ImageFileName=in(["powershell.exe", "pwsh.exe", "cmd.exe"])

// Multiple fields (OR across fields)
in(field=[ImageFileName, CommandLine], values=["powershell*", "cmd.exe"])

// Case insensitive
in(field=User, values=["ADMIN", "Administrator"], ignoreCase=true)
```
- **Use for**: Multiple discrete values (OR logic)
- **Performance**: Better than multiple `field=value` OR'd in `test()`

**Official ref**: [in() Function](https://library.humio.com/data-analysis/functions-in.html)

### 3.2.4 `test()` — Expression Evaluation 🔍
```cql
// Syntax: test(<boolean expression>)

// Field comparison
test(bytes_out > bytes_in)

// Arithmetic
test(bytes_total > 100000)

// Complex boolean
test((action="failure" AND attempts>5) OR (user="admin"))

// String functions
test(lower(ImageFileName)="powershell.exe")
test(match(CommandLine, "(?i)encodedcommand"))

// LIKE patterns
test(ImageFileName LIKE "power%")
test(host LIKE "DC0_")

// Field existence
test(field=User)        // field exists
test(not(field=User))   // field missing
```
- **Full expression language**: arithmetic, comparison, boolean, functions
- **Use when**: `in()`, `cidr()`, simple filters aren't sufficient
- **Performance**: Evaluates per event — filter with tag/field first

**Official ref**: [test() Function](https://library.humio.com/data-analysis/functions-test.html)

### 3.2.5 `cidr()` — IP Range Matching 🔍
```cql
// Syntax: cidr(field=<ip_field>, subnet=<array>)

// Private IPs
cidr(src_ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

// Cloud provider ranges (example)
cidr(dst_ip, subnet=["52.0.0.0/8", "54.0.0.0/8"])

// Negate for public IPs
not(cidr(src_ip, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16"]))
```
- **Optimized**: Uses IP trie for fast matching
- **Use for**: Network segmentation, threat intel matching

**Official ref**: [cidr() Function](https://library.humio.com/data-analysis/functions-cidr.html)

### 3.2.6 `match()` / `regex()` — Pattern Matching 🔍
```cql
// match() in test() — boolean filter
test(match(CommandLine, "(?i)encodedcommand"))
test(match(DomainName, ".*\\.tk$"))

// regex() as extraction (parsing role)
regex("(?<domain>[^.]+)\\.(?<tld>[^.]+)$", field=DomainName)

// Field filter with regex (prefix only)
CommandLine=/encodedcommand/i
```
- **`match()`**: Returns boolean — use in `test()` for filtering
- **`regex()`**: Extracts named groups — creates fields
- **Field filter regex**: `field=/pattern/` — prefix optimization possible

**Official ref**: [match() Function](https://library.humio.com/data-analysis/functions-match.html), [regex() Function](https://library.humio.com/data-analysis/functions-regex.html)

---

## 3.3 Transformation Functions 🔄

### 3.3.1 `:=` — Field Assignment 🔄
```cql
// Simple
newField := "static value"

// From existing field
fileName := lower(ImageFileName)

// Expression
bytes_total := bytes_in + bytes_out
ratio := bytes_out / bytes_in

// Conditional
is_suspicious := if(match(CommandLine, "(?i)encoded"), then=true, else=false)

// Function call
geo := ipLocation(src_ip)
```
- **Core transformation**: Creates or overwrites fields
- **Right side**: Any expression (literals, fields, math, function calls)
- **Chaining**: `a := b + 1 | c := a * 2`

### 3.3.2 `format()` — String Formatting 🔄
```cql
// printf-style formatting
summary := format("%s on %s: %s", field=[ImageFileName, ComputerName, CommandLine])

// Numbers with formatting
size_mb := format("%,.2f MB", field=[bytes_total/1024/1024])

// Zero padding
padded_id := format("%06d", field=[event_id])

// Date formatting (use formatTime for @timestamp)
date_str := format("%s", field=[formatTime("%Y-%m-%d", field=@timestamp)])
```
- **Format specifiers**: `%s` (string), `%d` (int), `%f` (float), `%,` (comma grouping)
- **Field array**: `field=[field1, field2, ...]` maps to `%s`, `%d` in order

**Official ref**: [format() Function](https://library.humio.com/data-analysis/functions-format.html)

### 3.3.3 `concat()` — String Concatenation 🔄
```cql
// Two fields
full_cmd := concat(ImageFileName, " ", CommandLine)

// Multiple fields with separator
cmdline := concat([ImageFileName, " ", CommandLine])

// Equivalent operator
full_cmd := ImageFileName + " " + CommandLine
```
- **Use `concat()` for arrays**, `+` operator for simple cases

**Official ref**: [concat() Function](https://library.humio.com/data-analysis/functions-concat.html)

### 3.3.4 `split()` / `splitString()` — String Splitting 🔄
```cql
// Split into array
parts := splitString(field=DomainName, by=".")

// Access array elements
tld := getArrayElement(array=parts, index=-1)  // last element
subdomain := getArrayElement(array=parts, index=0)  // first element

// Array length
num_parts := array:length(parts)
```
- **Returns array**: Use `getArrayElement()`, `array:length()`, `array:filter()`

**Official ref**: [splitString() Function](https://library.humio.com/data-analysis/functions-split.html)

### 3.3.5 `lower()` / `upper()` — Case Conversion 🔄
```cql
file_lower := lower(ImageFileName)
domain_upper := upper(DomainName)
user_normalized := lower(User)
```
- **Use for**: Case-insensitive comparisons, normalization

**Official ref**: [lower() Function](https://library.humio.com/data-analysis/functions-lower.html)

### 3.3.6 `replace()` — String Replacement 🔄
```cql
// Regex replace (mask sensitive data)
clean_cmd := replace(field=CommandLine, with="***", regex="(?i)password=\\S+")

// Remove prefix
clean_path := replace(field=FilePath, with="", regex="^C:\\\\Users\\\\[^\\\\]+\\\\")

// Simple string replace (no regex)
normalized := replace(field=host, with="-", string=".")
```
- **`regex` parameter**: PCRE2 regex
- **`string` parameter**: Literal string replacement

**Official ref**: [replace() Function](https://library.humio.com/data-analysis/functions-replace.html)

### 3.3.7 `eval()` — Expression Evaluation 🔄
```cql
// Complex expressions in one call
eval(
  total_bytes := bytes_in + bytes_out,
  ratio := bytes_out / bytes_in,
  is_anomaly := if(ratio > 10, then=true, else=false)
)
```
- **Multiple assignments** in one function
- **Use for**: Complex multi-step transformations

**Official ref**: [eval() Function](https://library.humio.com/data-analysis/functions-eval.html)

---

## 3.4 Aggregation Functions 📊

### 3.4.1 `groupBy()` — Core Aggregation 📊
```cql
// Syntax: groupBy(field=[<fields>], function=<aggregation>, limit=<int>)

// Single field, count
groupBy([ComputerName], function=count())

// Multiple fields
groupBy([ComputerName, ImageFileName], function=count())

// Multiple aggregations
groupBy(
  [ComputerName],
  function=[
    count(as=event_count),
    sum(field=bytes_total, as=total_bytes),
    avg(field=bytes_total, as=avg_bytes),
    min(field=@timestamp, as=first_seen),
    max(field=@timestamp, as=last_seen),
    collect(field=ImageFileName, as=processes, limit=100)
  ],
  limit=10000
)
```
- **`limit` is REQUIRED for production**: Prevents memory exhaustion
- **Default limit**: 200,000 (configurable)
- **`limit=max`**: Only for small, known cardinality

**Official ref**: [groupBy() Function](https://library.humio.com/data-analysis/functions-groupby.html)

### 3.4.2 `count()` / `sum()` / `avg()` / `min()` / `max()` 📊
```cql
// Used inside groupBy(), bucket(), timeChart(), stats()
function=[
  count(as=total_events),
  sum(field=bytes, as=total_bytes),
  avg(field=bytes, as=avg_bytes),
  min(field=@timestamp, as=earliest),
  max(field=@timestamp, as=latest)
]
```
- **`count()`**: Counts events (no field needed)
- **`sum/avg/min/max`**: Require `field=` parameter

**Official ref**: [count()](https://library.humio.com/data-analysis/functions-count.html), [sum()](https://library.humio.com/data-analysis/functions-sum.html), [avg()](https://library.humio.com/data-analysis/functions-avg.html)

### 3.4.3 `stats()` — Multiple Aggregations 📊
```cql
// Alternative to groupBy with by= clause
stats(
  count(as=total),
  sum(bytes, as=total_bytes),
  avg(bytes, as=avg_bytes),
  by=[host, sourcetype]
)
```
- **Similar to `groupBy`** but different syntax
- **Use when**: You prefer SQL-style `by=` syntax

**Official ref**: [stats() Function](https://library.humio.com/data-analysis/functions-stats.html)

### 3.4.4 `collect()` — Collect Field Values 📊
```cql
// Collect single field
groupBy([ComputerName], function=collect(ImageFileName, limit=1000))

// Collect multiple fields
groupBy([ComputerName], function=collect([ImageFileName, CommandLine, ProcessId], limit=1000))

// With alias
groupBy([ComputerName], function=collect(ImageFileName, as=processes, limit=1000))
```
- **Returns array**: Use `array:length()`, `getArrayElement()` to inspect
- **`limit` is critical**: Prevents massive arrays

**Official ref**: [collect() Function](https://library.humio.com/data-analysis/functions-collect.html)

### 3.4.5 `top()` / `rare()` — Top/Bottom Values 📊
```cql
// Top N by count (post-aggregation)
groupBy([ImageFileName], function=count())
| top(10, field=_count)

// Rare values
groupBy([User], function=count())
| rare(5, field=_count)
```
- **Post-aggregation functions**: Run after `groupBy()`
- **`field=`**: The field to sort by

**Official ref**: [top() Function](https://library.humio.com/data-analysis/functions-top.html)

### 3.4.6 `bucket()` — Time Bucketing 📊
```cql
// Time buckets with aggregation
#event_simpleName=ProcessRollup2
| bucket(span=1h, function=count())

// Multiple aggregations per bucket
bucket(
  span=1h,
  function=[
    count(),
    sum(bytes),
    collect(ImageFileName, limit=100)
  ]
)

// Bucket by field + time
bucket(span=1h, function=count(), by=[host])
```
- **`span`**: Duration (1m, 5m, 1h, 1d, etc.)
- **Optimized for time-series**: Better than `groupBy(@timestamp/3600000)`

**Official ref**: [bucket() Function](https://library.humio.com/data-analysis/functions-bucket.html)

### 3.4.7 `timeChart()` — Time Series Visualization 📊
```cql
// Basic time chart
#event_simpleName=ProcessRollup2
| timeChart(span=1h, function=count())

// By series (creates multiple lines)
| timeChart(span=1h, function=count(), series=ImageFileName)

// Multiple functions
| timeChart(span=1h, function=[count(), sum(bytes)], series=action)

// With limit on series
| timeChart(span=1h, function=count(), series=ImageFileName, limit=20)
```
- **Dashboard-optimized**: Returns data formatted for time chart widgets
- **`series`**: Field to split lines by
- **`limit`**: Max series to return

**Official ref**: [timeChart() Function](https://library.humio.com/data-analysis/functions-timechart.html)

---

## 3.5 Parsing Functions 📝

### 3.5.1 `parseJson()` 📝
```cql
// Parse JSON from @rawstring or field
parseJson(field=@rawstring)

// Parse specific field
parseJson(field=Message)

// Keep original field
parseJson(field=Message, prefix="json_")
```
- **Creates fields** from JSON keys
- **Nested objects**: Flattened with `.` notation

**Official ref**: [parseJson() Function](https://library.humio.com/data-analysis/functions-parsejson.html)

### 3.5.2 `kvParse()` 📝
```cql
// Parse key=value pairs
kvParse(field=@rawstring)

// Custom delimiters
kvParse(field=@rawstring, pairDelimiter="&", keyValueDelimiter="=")

// Prefix fields
kvParse(field=@rawstring, prefix="kv_")
```
- **Handles**: `key=value`, `key="value"`, `key='value'`
- **Common for**: Syslog, application logs, query strings

**Official ref**: [kvParse() Function](https://library.humio.com/data-analysis/functions-kvparse.html)

### 3.5.3 `splitString()` 📝
```cql
// Split into array (see Transformation section)
parts := splitString(field=DomainName, by=".")
```
- **Returns array**: Use array functions to process

**Official ref**: [splitString() Function](https://library.humio.com/data-analysis/functions-split.html)

### 3.5.4 `regex()` with Named Groups 📝
```cql
// Extract multiple fields at once
regex("(?<user>\\w+)\\s+logon\\s+(?<type>\\w+)", field=@rawstring)

// Complex extraction
regex("(?<ip>\\d+\\.\\d+\\.\\d+\\.\\d+):(?<port>\\d+)", field=NetworkAddress)

// From specific field
regex("(?<domain>[^.]+)\\.(?<tld>[^.]+)$", field=DomainName)
```
- **PCRE2 regex**: Full Perl-compatible regex
- **Named groups**: `(?<name>pattern)` create fields
- **Use in parser** for index-time extraction, **or in query** for search-time

**Official ref**: [regex() Function](https://library.humio.com/data-analysis/functions-regex.html)

---

## 3.6 Enrichment Functions 🌐

### 3.6.1 `ipLocation()` 🌐
```cql
// Enrich with geolocation
ipLocation(src_ip, as=geo)

// Fields created: geo.country, geo.city, geo.lat, geo.lon, geo.region
```
- **Built-in MaxMind GeoIP2 database**
- **Fields**: `country`, `city`, `lat`, `lon`, `region`, `postalCode`

**Official ref**: [ipLocation() Function](https://library.humio.com/data-analysis/functions-iplocation.html)

### 3.6.2 `asn()` 🌐
```cql
// Enrich with ASN info
asn(src_ip, as=asn_info)

// Fields: asn_info.asn (number), asn_info.org (organization name)
```
- **Built-in ASN database**
- **Use for**: Identifying hosting providers, VPNs, corporate networks

**Official ref**: [asn() Function](https://library.humio.com/data-analysis/functions-asn.html)

### 3.6.3 `cidr()` (Enrichment) 🌐
```cql
// Add network context
cidr(src_ip, subnet=["10.0.0.0/8"], as=network)
// Creates: network=true/false
```
- **Can be used for enrichment** with `as=` parameter

**Official ref**: [cidr() Function](https://library.humio.com/data-analysis/functions-cidr.html)

### 3.6.4 `rdns()` 🌐
```cql
// Reverse DNS lookup
rdns(src_ip, as=rdns_result)
// Creates: rdns_result (hostname)
```
- **Network call**: May add latency
- **Use sparingly** in high-volume queries

**Official ref**: [rdns() Function](https://library.humio.com/data-analysis/functions-rdns.html)

### 3.6.5 `geoHash()` 🌐
```cql
// Geohash for spatial clustering
geoHash(lat=geo.lat, lon=geo.lon, precision=5, as=geohash)
// Creates: geohash (string like "dr5reg")
```
- **Precision 1-12**: Higher = more precise
- **Use for**: Geographic clustering, mapping

**Official ref**: [geoHash() Function](https://library.humio.com/data-analysis/functions-geohash.html)

### 3.6.6 `match()` — Lookup Table Enrichment 🌐
```cql
// Enrich from CSV lookup file
match(file="indicators.csv", column="ioc", field=FileHash, include=["threat_name", "severity"])

// Strict=false: keep events without match
match(file="indicators.csv", column="ioc", field=FileHash, include=["threat_name"], strict=false)

// Multiple columns
match(file="assets.csv", column="ip", field=src_ip, include=["owner", "department", "criticality"])
```
- **CSV file must be uploaded** to LogScale (Files UI or API)
- **`column`**: Lookup column in CSV
- **`field`**: Event field to match
- **`include`**: CSV columns to add
- **`strict=false`**: Left join (keep unmatched)

**Official ref**: [match() Function](https://library.humio.com/data-analysis/functions-match.html)

### 3.6.7 `join()` — Subquery Correlation 🌐
```cql
// Inner join (default)
join(
  subquery={
    #event_simpleName=ProcessRollup2
    | groupBy([ProcessId], function=tail(1))
  },
  field=ProcessId,
  include=[ImageFileName, CommandLine, User]
)

// Left join
join(
  subquery={...},
  field=ProcessId,
  include=[...],
  mode=left
)
```
- **⚠️ 200,000 ROW HARD LIMIT** on subquery results — silently truncates!
- **Runs sequentially**: Main query waits for subquery
- **Not for high-cardinality joins** — use `defineTable()` + `match()` instead

**Official ref**: [join() Function](https://library.humio.com/data-analysis/functions-join.html)

### 3.6.8 `selfJoin()` — High-Cardinality Self-Join 🌐
```cql
// Find parent-child process relationships
selfJoin(
  field=ProcessId,
  where=[
    { #event_simpleName=ProcessRollup2 | ParentProcessId=* },
    { #event_simpleName=ProcessRollup2 | ImageFileName="powershell.exe" }
  ],
  include=[ImageFileName, CommandLine, User, ParentProcessId]
)

// With selfJoinFilter for pre-filtering
selfJoinFilter(
  field=ProcessId,
  where=[
    { #event_simpleName=ProcessRollup2 },
    { #event_simpleName=ProcessRollup2 | ImageFileName="powershell.exe" }
  ],
  include=[ImageFileName, CommandLine, User]
)
```
- **Optimized for high cardinality**: Uses filter-first approach
- **No 200k limit** (within memory limits)
- **`where` array**: Each element is a filter pipeline

**Official ref**: [selfJoin() Function](https://library.humio.com/data-analysis/functions-selfjoin.html), [selfJoinFilter()](https://library.humio.com/data-analysis/functions-selfjoinfilter.html)

### 3.6.9 `readFile()` — Lookup File Access 🌐
```cql
// Read CSV file directly
readFile("assets.csv")

// With field selection
readFile("assets.csv", include=["ip", "owner", "department"])

// Combine with match()
readFile("assets.csv")
| match(field=src_ip, column="ip", include=["owner", "department"])
```
- **Reads uploaded CSV/JSON files**
- **Use with `match()`** for enrichment
- **Alternative to `defineTable()`** for static data

**Official ref**: [readFile() Function](https://library.humio.com/data-analysis/functions-readfile.html)

---

## 3.7 Visualization & Output Functions 📈

### 3.7.1 `table()` 📈
```cql
// Tabular output (aggregation — reduces rows)
table([ComputerName, ImageFileName, _count], limit=1000)

// With formatting
groupBy([ComputerName], function=count())
| table([ComputerName, _count], limit=100)
```
- **Aggregation function**: Reduces to one row per group
- **`limit`**: Max rows (default 200)
- **Dashboard widget**: Table widget

**Official ref**: [table() Function](https://library.humio.com/data-analysis/functions-table.html)

### 3.7.2 `select()` 📈
```cql
// Pluck fields (no aggregation — keeps all events)
select([@timestamp, ComputerName, ImageFileName, CommandLine])

// Rename while selecting
select([@timestamp, ComputerName as Host, ImageFileName as Process])
```
- **Non-aggregating**: Keeps event granularity
- **Use for**: Event lists, passing to other functions

**Official ref**: [select() Function](https://library.humio.com/data-analysis/functions-select.html)

### 3.7.3 `rename()` 📈
```cql
// Single
rename(field=ImageFileName, as=ProcessName)

// Multiple
rename(field=[ImageFileName, ComputerName], as=[ProcessName, Host])
```
- **In-place rename**: Modifies field names

**Official ref**: [rename() Function](https://library.humio.com/data-analysis/functions-rename.html)

### 3.7.4 `drop()` 📈
```cql
// Single
drop(@rawstring)

// Multiple
drop([@id, @ingesttimestamp, _count])
```
- **Remove fields** from output

**Official ref**: [drop() Function](https://library.humio.com/data-analysis/functions-drop.html)

### 3.7.5 `sort()` 📈
```cql
// Descending
sort(_count, order=desc)

// Ascending
sort(@timestamp, order=asc)

// Multiple fields
sort([ComputerName, _count], order=[asc, desc])
```

**Official ref**: [sort() Function](https://library.humio.com/data-analysis/functions-sort.html)

### 3.7.6 `head()` / `tail()` 📈
```cql
// First N
head(10)

// Last N
tail(10)
```

**Official ref**: [head() Function](https://library.humio.com/data-analysis/functions-head.html)

### 3.7.7 `formatTime()` 📈
```cql
// Format @timestamp for display
formatted := formatTime("%Y-%m-%d %H:%M:%S", field=@timestamp, timezone="UTC", locale="en_US")

// Just date
date_only := formatTime("%Y-%m-%d", field=@timestamp)

// Timezone conversion
local_time := formatTime("%H:%M:%S", field=@timestamp, timezone="America/New_York")
```
- **Timezone**: IANA timezone names (UTC, America/New_York, Europe/London)
- **Locale**: Affects month/day names

**Official ref**: [formatTime() Function](https://library.humio.com/data-analysis/functions-formattime.html)

---

## 3.8 Quick Function Lookup Table

| Need | Function | Role |
|------|----------|------|
| Tag filter | `#tag=value` | 🔍 |
| Field filter | `field=value` | 🔍 |
| Multiple values (OR) | `in(field, values=[...])` | 🔍 |
| Complex boolean | `test(expression)` | 🔍 |
| IP range | `cidr(ip, subnet=[...])` | 🔍 |
| Regex filter | `test(match(field, "regex"))` | 🔍 |
| Field assignment | `new := expression` | 🔄 |
| Format string | `format("%s", field=[...])` | 🔄 |
| Concat strings | `concat(a, " ", b)` | 🔄 |
| Split string | `splitString(field, by=".")` | 🔄 |
| Lowercase | `lower(field)` | 🔄 |
| Replace (regex) | `replace(field, with="", regex="")` | 🔄 |
| Group & count | `groupBy([field], function=count())` | 📊 |
| Multiple aggs | `groupBy([f], function=[count(), sum(x)])` | 📊 |
| Collect values | `collect(field, limit=1000)` | 📊 |
| Time buckets | `bucket(span=1h, function=count())` | 📊 |
| Time chart | `timeChart(span=1h, function=count())` | 📊 |
| Parse JSON | `parseJson(field=@rawstring)` | 📝 |
| Parse KV | `kvParse(field=@rawstring)` | 📝 |
| Regex extract | `regex("(?<f>...)", field=@rawstring)` | 📝 |
| GeoIP | `ipLocation(ip, as=geo)` | 🌐 |
| ASN | `asn(ip, as=asn)` | 🌐 |
| RDNS | `rdns(ip, as=rdns)` | 🌐 |
| Lookup CSV | `match(file="x.csv", column="c", field=f)` | 🌐 |
| Join subquery | `join(subquery={...}, field=f)` | 🌐 |
| Self-join | `selfJoin(field=f, where=[...])` | 🌐 |
| Read file | `readFile("x.csv")` | 🌐 |
| Table output | `table([fields], limit=200)` | 📈 |
| Select fields | `select([fields])` | 📈 |
| Rename | `rename(field=old, as=new)` | 📈 |
| Drop fields | `drop([fields])` | 📈 |
| Sort | `sort(field, order=desc)` | 📈 |
| Limit | `head(N)` / `tail(N)` | 📈 |
| Format time | `formatTime("%Y-%m-%d", field=@timestamp)` | 📈 |

---

## 3.9 What's Next

- **Chapter 4**: Threat hunting patterns mapped to MITRE ATT&CK
- **Chapter 5**: Joins, lookups, and multi-event correlation deep dive
- **Chapter 6**: Dashboards and visualization
- **Chapter 7**: Performance optimization and reference tables

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 4 — Threat Hunting Patterns & MITRE ATT&CK Mapping

---

## 4.1 Why Threat Hunting in LogScale?

LogScale's **tagged field indexing**, **streaming architecture**, and **built-in enrichment** (GeoIP, ASN, RDNS) make it uniquely suited for threat hunting at scale. Unlike SIEMs that require pre-aggregation, LogScale lets you hunt over raw events with sub-second tag filtering.

**Hunting philosophy**: Start with tagged fields → narrow with field filters → enrich → correlate → visualize.

---

## 4.2 The Golden Rule: Tag Filters First

```cql
// ALWAYS start with tag filters
#event_simpleName=ProcessRollup2
#repo=windows

// THEN field filters
| ImageFileName=in(["powershell.exe", "pwsh.exe", "cmd.exe"])

// THEN complex filters
| test(match(CommandLine, "(?i)(encodedcommand|bypass|hidden)"))

// THEN enrich
| ipLocation(OriginSourceIpAddress, as=geo)
| asn(OriginSourceIpAddress, as=asn)

// THEN aggregate
| groupBy([ComputerName, ImageFileName], function=count(), limit=10000)
```

---

## 4.3 Process Execution Hunting

### 4.3.1 Suspicious Process Chains (T1059, T1059.001, T1059.003)
```cql
// Parent-child chain: Office → PowerShell → Suspicious
#event_simpleName=ProcessRollup2
| ImageFileName=in(["WINWORD.EXE", "EXCEL.EXE", "OUTLOOK.EXE", "MSACCESS.EXE"])
| ParentProcessId=*
| selfJoinFilter(
  field=ProcessId,
  where=[
    { #event_simpleName=ProcessRollup2 | ParentProcessId=* },
    { #event_simpleName=ProcessRollup2 | ImageFileName=in(["powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe"]) }
  ],
  include=[ImageFileName, CommandLine, User, ParentProcessId, ComputerName]
)
| groupBy([ComputerName, User], function=collect([ImageFileName, CommandLine]))
```

**MITRE**: T1059 (Command and Scripting Interpreter), T1059.001 (PowerShell), T1059.003 (Windows Command Shell)

### 4.3.2 Living Off The Land Binaries (LOLBins) (T1218)
```cql
// Microsoft signed binaries abused for execution
#event_simpleName=ProcessRollup2
| ImageFileName=in([
  "mshta.exe", "regsvr32.exe", "rundll32.exe", "regasm.exe",
  "installutil.exe", "msbuild.exe", "csc.exe", "vbc.exe",
  "wmic.exe", "certutil.exe", "bitsadmin.exe", "schtasks.exe"
])
| test(match(CommandLine, "(?i)(http|ftp|\\.dll|\\.sct|\\.xml|/download|/url)"))
| ipLocation(OriginSourceIpAddress, as=geo)
| asn(OriginSourceIpAddress, as=asn)
| groupBy([ComputerName, ImageFileName], function=[count(), collect([CommandLine, geo.country, asn.org])])
| sort(_count, order=desc)
```

**MITRE**: T1218 (System Binary Proxy Execution)

### 4.3.3 PowerShell Encoded Commands (T1059.001, T1027)
```cql
#event_simpleName=ProcessRollup2
| ImageFileName=in(["powershell.exe", "pwsh.exe"])
| test(match(CommandLine, "(?i)(-enc\\s+|-encodedcommand\\s+|-e\\s+)[A-Za-z0-9+/]+={0,2}"))
| fileName := lower(ImageFileName)
| decoded := replace(field=CommandLine, with="", regex="(?i)(-enc(odedcommand)?|-e)\\s+")
| groupBy([ComputerName, User], function=[count(), collect([CommandLine, decoded])])
```

**MITRE**: T1059.001 (PowerShell), T1027 (Obfuscated/Stored Files)

### 4.3.4 WMI & WMIC Abuse (T1047, T1546.003)
```cql
// WMI process creation
#event_simpleName=ProcessRollup2
| ImageFileName=in(["wmiprvse.exe", "wmic.exe"])
| test(match(CommandLine, "(?i)(process\\s+call\\s+create|/create)"))
| groupBy([ComputerName, User, ImageFileName], function=[count(), collect(CommandLine)])

// WMIC remote execution
#event_simpleName=ProcessRollup2
| ImageFileName="wmic.exe"
| test(match(CommandLine, "(?i)(/node:|/user:|/password:)"))
| groupBy([ComputerName], function=[count(), collect(CommandLine)])
```

**MITRE**: T1047 (WMI), T1546.003 (WMI Event Subscription)

---

## 4.4 Network Hunting

### 4.4.1 Beaconing Detection (T1071, T1071.001)
```cql
// Regular interval connections (potential beaconing)
#event_simpleName=NetworkConnectIP4
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8"]))
| RemotePort=in([80, 443, 8080, 8443])
| bucket(span=5m, function=count(), by=[ComputerName, RemoteAddressIP4, RemotePort])
| test(_count > 10)  // More than 10 connections per 5min
| sort(_count, order=desc)
| ipLocation(RemoteAddressIP4, as=geo)
| asn(RemoteAddressIP4, as=asn)
| groupBy([ComputerName, RemoteAddressIP4], function=[sum(_count, as=total_conns), collect([geo.country, asn.org, RemotePort])])
```

**MITRE**: T1071 (Application Layer Protocol), T1071.001 (Web Protocols)

### 4.4.2 Suspicious DNS (T1071.004, T1568)
```cql
// Long subdomains, high entropy, DGA-like
#event_simpleName=DnsRequest
| RequestType=in([1, 28])  // A, AAAA
| test(length(DomainName) > 50)
| entropy := eval(entropy=entropy(DomainName))  // Requires custom function or approximation
| test(entropy > 3.5)
| groupBy([ComputerName, DomainName], function=[count(), collect(RequestType)])
| sort(_count, order=desc)

// Fast-flux / many IPs for one domain
#event_simpleName=DnsRequest
| groupBy([DomainName], function=[count(), collect(ResolvedAddress), dc(ResolvedAddress, as=unique_ips)])
| test(unique_ips > 20)
```

**MITRE**: T1071.004 (DNS), T1568 (Dynamic Resolution)

### 4.4.3 Non-Standard Ports (T1065, T1571)
```cql
#event_simpleName=NetworkConnectIP4
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))
| not(RemotePort=in([80, 443, 53, 22, 25, 110, 143, 993, 995, 3389, 445, 135, 139, 5985, 5986]))
| ipLocation(RemoteAddressIP4, as=geo)
| asn(RemoteAddressIP4, as=asn)
| groupBy([ComputerName, RemoteAddressIP4, RemotePort], function=[count(), collect([ProcessName, geo.country, asn.org])])
| sort(_count, order=desc)
```

**MITRE**: T1065 (Uncommonly Used Port), T1571 (Non-Standard Port)

---

## 4.5 Authentication & Access Hunting

### 4.5.1 Brute Force / Password Spray (T1110, T1110.001, T1110.003)
```cql
// Failed logons from single source to multiple users (password spray)
#event_simpleName=UserLogonFailed
| groupBy([SourceIp, ComputerName], function=[count(), collect(User, limit=100), dc(User, as=unique_users)])
| test(unique_users > 5 AND _count > 10)
| ipLocation(SourceIp, as=geo)
| asn(SourceIp, as=asn)
| sort(_count, order=desc)

// Failed logons for single user from multiple sources (brute force)
#event_simpleName=UserLogonFailed
| groupBy([User, ComputerName], function=[count(), collect(SourceIp, limit=100), dc(SourceIp, as=unique_ips)])
| test(unique_ips > 3 AND _count > 20)
| sort(_count, order=desc)
```

**MITRE**: T1110 (Brute Force), T1110.001 (Password Guessing), T1110.003 (Password Spraying)

### 4.5.2 Impossible Travel (T1550, T1078)
```cql
// Successful logons from geographically distant locations within short time
#event_simpleName=UserLogon
| ipLocation(SourceIp, as=geo)
| sort(User, @timestamp)
| // Calculate distance/time between consecutive logons per user
// Requires sessionization - see Chapter 5 for selfJoin pattern
```

**MITRE**: T1550 (Use Alternate Authentication Material), T1078 (Valid Accounts)

### 4.5.3 Privilege Escalation (T1068, T1548)
```cql
// Process token manipulation, UAC bypass
#event_simpleName=ProcessRollup2
| ImageFileName=in(["consent.exe", "useraccountcontrolsettings.exe"])
| test(match(CommandLine, "(?i)(/auto|/force|bypass)"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])

// Token manipulation via known tools
#event_simpleName=ProcessRollup2
| ImageFileName=in(["sekurlsa.exe", "mimikatz.exe", "rubeus.exe", "tokens.exe"])
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])
```

**MITRE**: T1068 (Exploitation for Privilege Escalation), T1548 (Abuse Elevation Control Mechanism)

---

## 4.6 Persistence Hunting

### 4.6.1 Scheduled Tasks (T1053.005)
```cql
// Task creation via schtasks or COM
#event_simpleName=ProcessRollup2
| ImageFileName=in(["schtasks.exe", "taskeng.exe"])
| test(match(CommandLine, "(?i)(/create|/sc\\s+|/tr\\s+)"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])

// Task registration events
#event_simpleName=ScheduledTaskRegistered
| groupBy([ComputerName, TaskName], function=[count(), collect([User, Action, Trigger])])
```

**MITRE**: T1053.005 (Scheduled Task)

### 4.6.2 Registry Run Keys (T1547.001)
```cql
// Registry modification for persistence
#event_simpleName=RegistryValueSet
| TargetObject=/Run$/i
| groupBy([ComputerName, TargetObject], function=[count(), collect([User, ImageFileName, ValueData])])

// Via reg.exe
#event_simpleName=ProcessRollup2
| ImageFileName="reg.exe"
| test(match(CommandLine, "(?i)(add.*run|add.*runonce)"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])
```

**MITRE**: T1547.001 (Registry Run Keys / Startup Folder)

### 4.6.3 Service Installation (T1543.003)
```cql
// Service creation
#event_simpleName=ServiceInstalled
| groupBy([ComputerName, ServiceName], function=[count(), collect([User, ImagePath, StartType])])

// Via sc.exe
#event_simpleName=ProcessRollup2
| ImageFileName="sc.exe"
| test(match(CommandLine, "(?i)create"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])
```

**MITRE**: T1543.003 (Windows Service)

---

## 4.7 Defense Evasion Hunting

### 4.7.1 Log Clearing (T1070.001)
```cql
// Security log cleared
#event_simpleName=SecurityLogCleared
| groupBy([ComputerName], function=[count(), collect([User, @timestamp])])

// Wevtutil clear
#event_simpleName=ProcessRollup2
| ImageFileName="wevtutil.exe"
| test(match(CommandLine, "(?i)cl(ean|ear)"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])
```

**MITRE**: T1070.001 (Clear Windows Event Logs)

### 4.7.2 Process Injection (T1055)
```cql
// Cross-process memory access (OpenProcess + WriteProcessMemory)
#event_simpleName=ProcessRollup2
| ImageFileName=in(["rundll32.exe", "regsvr32.exe", "powershell.exe"])
| test(match(CommandLine, "(?i)(inject|createremotethread|writeprocessmemory|virtualallocex)"))
| groupBy([ComputerName, ImageFileName], function=[count(), collect(CommandLine)])
```

**MITRE**: T1055 (Process Injection)

### 4.7.3 Signed Binary Proxy Execution (T1218)
```cql
// Already covered in 4.3.2 LOLBins
// Additional: msxsl.exe, cscript.exe, wscript.exe with remote scripts
#event_simpleName=ProcessRollup2
| ImageFileName=in(["msxsl.exe", "cscript.exe", "wscript.exe"])
| test(match(CommandLine, "(?i)(http|ftp|\\.wsf|\\.js|\\.vbs)"))
| groupBy([ComputerName, ImageFileName], function=[count(), collect(CommandLine)])
```

**MITRE**: T1218 (System Binary Proxy Execution)

---

## 4.8 Discovery & Collection Hunting

### 4.8.1 System Discovery (T1082, T1083, T1057)
```cql
// System info enumeration
#event_simpleName=ProcessRollup2
| ImageFileName=in(["systeminfo.exe", "whoami.exe", "net.exe", "net1.exe", "wmic.exe"])
| test(match(CommandLine, "(?i)(group|user|computer|os|process|service)"))
| groupBy([ComputerName, ImageFileName], function=[count(), collect(CommandLine)])
```

**MITRE**: T1082 (System Information Discovery), T1083 (File and Directory Discovery), T1057 (Process Discovery)

### 4.8.2 Archive Collection (T1560)
```cql
// Archive creation
#event_simpleName=ProcessRollup2
| ImageFileName=in(["7z.exe", "7za.exe", "winrar.exe", "rar.exe", "tar.exe", "gzip.exe"])
| test(match(CommandLine, "(?i)(a|add|create)"))
| groupBy([ComputerName, User], function=[count(), collect(CommandLine)])
```

**MITRE**: T1560 (Archive Collected Data)

---

## 4.9 Command & Control Hunting

### 4.9.1 DNS Tunneling (T1071.004)
```cql
// High volume DNS with long subdomains
#event_simpleName=DnsRequest
| RequestType=in([16, 255])  // TXT, ANY
| test(length(DomainName) > 100)
| groupBy([ComputerName, DomainName], function=[count(), collect(RequestType)])
| sort(_count, order=desc)
```

**MITRE**: T1071.004 (DNS)

### 4.9.2 Non-Application Layer Protocol (T1095)
```cql
// ICMP, raw sockets, custom protocols
#event_simpleName=NetworkConnectIP4
| Protocol=in([1, 58])  // ICMPv4, ICMPv6
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))
| groupBy([ComputerName, RemoteAddressIP4], function=[count(), collect(Protocol)])
```

**MITRE**: T1095 (Non-Application Layer Protocol)

---

## 4.10 Exfiltration Hunting

### 4.10.1 Data Exfiltration Over Web (T1041)
```cql
// Large uploads to external destinations
#event_simpleName=NetworkConnectIP4
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))
| RemotePort=in([80, 443, 8080, 8443])
| bytes_out > 10000000  // > 10MB
| ipLocation(RemoteAddressIP4, as=geo)
| asn(RemoteAddressIP4, as=asn)
| groupBy([ComputerName, RemoteAddressIP4], function=[sum(bytes_out, as=total_out), collect([geo.country, asn.org, RemotePort])])
| sort(total_out, order=desc)
```

**MITRE**: T1041 (Exfiltration Over Command and Control Channel)

### 4.10.2 Cloud Storage Exfiltration (T1567)
```cql
// Uploads to known cloud storage
#event_simpleName=NetworkConnectIP4
| cidr(RemoteAddressIP4, subnet=[
  "52.0.0.0/8", "54.0.0.0/8",    // AWS
  "13.0.0.0/8", "20.0.0.0/8",    // Azure
  "34.0.0.0/8", "35.0.0.0/8"     // GCP
])
| RemotePort=in([80, 443])
| bytes_out > 5000000
| groupBy([ComputerName, RemoteAddressIP4], function=[sum(bytes_out, as=total_out), collect(RemotePort)])
| sort(total_out, order=desc)
```

**MITRE**: T1567 (Exfiltration Over Web Service)

---

## 4.11 MITRE ATT&CK Mapping Table

| Technique ID | Technique Name | CQL Pattern | Chapter Section |
|--------------|----------------|-------------|-----------------|
| T1059.001 | PowerShell | Encoded commands, suspicious params | 4.3.3 |
| T1059.003 | Windows Command Shell | cmd.exe with suspicious args | 4.3.1 |
| T1059.005 | Visual Basic | wscript/cscript with remote scripts | 4.7.3 |
| T1053.005 | Scheduled Task | schtasks.exe /create, TaskRegistered | 4.6.1 |
| T1055 | Process Injection | OpenProcess + WriteProcessMemory | 4.7.2 |
| T1071.001 | Web Protocols | Beaconing to HTTP/HTTPS | 4.4.1 |
| T1071.004 | DNS | DNS tunneling, DGA, fast-flux | 4.4.2, 4.9.1 |
| T1082 | System Info Discovery | systeminfo, whoami, wmic | 4.8.1 |
| T1095 | Non-App Layer Protocol | ICMP, raw sockets | 4.9.2 |
| T1110.001 | Password Guessing | Failed logons single user multi-source | 4.5.1 |
| T1110.003 | Password Spraying | Failed logons single source multi-user | 4.5.1 |
| T1218 | System Binary Proxy | LOLBins (mshta, regsvr32, etc.) | 4.3.2 |
| T1543.003 | Windows Service | sc.exe create, ServiceInstalled | 4.6.3 |
| T1547.001 | Registry Run Keys | reg.exe add Run, RegistryValueSet | 4.6.2 |
| T1550 | Alternate Auth Material | Impossible travel, pass-the-hash | 4.5.2 |
| T1560 | Archive Collected Data | 7z, winrar, tar with create | 4.8.2 |
| T1567 | Exfil to Cloud | Large uploads to AWS/Azure/GCP | 4.10.2 |
| T1568 | Dynamic Resolution | DGA, fast-flux DNS | 4.4.2 |
| T1571 | Non-Standard Port | Connections on uncommon ports | 4.4.3 |

---

## 4.12 Detection Engineering Best Practices

1. **Always use tag filters first** — `#event_simpleName=` is indexed
2. **Limit cardinality** — `groupBy(..., limit=10000)` prevents OOM
3. **Filter before enrich** — `ipLocation()` on 1M events is slow; filter to 1K first
4. **Use `defineTable()` + `match()` for reference sets** — Not `join()` (200k limit)
5. **Test with synthetic data** — `createEvents()` for unit testing detections
6. **Document MITRE mapping** — Include technique IDs in detection names/comments
7. **Version control detections** — Store as code (Git), not just in UI

---

## 4.13 Performance-Aware Hunting

| Anti-Pattern | Problem | Fix |
|--------------|---------|-----|
| `groupBy([User])` no limit | High cardinality → OOM | `groupBy([User], limit=10000)` |
| `join()` on high-cardinality field | 200k row limit → silent truncation | `defineTable()` + `match()` |
| `ipLocation()` on full dataset | Network calls per event → timeout | Filter to <10K events first |
| `sort()` before `head()` | Sorts all, then limits | `sort() | head()` is OK; `head()` after aggregation |
| `timeChart()` without filter | Charts all time → slow | Add tag/field filters first |

---

## 4.14 What's Next

- **Chapter 5**: Joins, lookups, and multi-event correlation deep dive
- **Chapter 6**: Dashboards and visualization
- **Chapter 7**: Performance optimization and reference tables

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 5 — Joins, Lookups & Multi-Event Correlation

---

## 5.1 Why Correlation in LogScale?

Security detection requires correlating **multiple event types**: process + network, auth + process, parent + child. LogScale provides three correlation methods with different trade-offs.

---

## 5.2 Join Types Overview

| Method | Max Rows | Cardinality | Execution | Best For |
|--------|----------|-------------|-----------|----------|
| `join()` | 200,000 (hard limit) | Low-Medium | Sequential | Small reference sets, exact matches |
| `selfJoin()` | Memory-bound | High | Optimized filter-first | Parent-child, sessionization |
| `defineTable()` + `match()` | No hard limit | Any | Parallel | Reference sets, enrichment, large lookups |

---

## 5.3 `join()` — Subquery Correlation

### 5.3.1 Inner Join (Default)
```cql
// Enrich process events with user details from auth events
#event_simpleName=ProcessRollup2
| join(
  subquery={
    #event_simpleName=UserLogon
    | groupBy([User], function=tail(1))
    | select([User, ComputerName, SourceIp])
  },
  field=User,
  include=[ComputerName, SourceIp]
)
```
- **Inner join**: Only events with matches in both sides
- **Subquery runs first**, then main query filters to matching keys

### 5.3.2 Left Join
```cql
// Keep all process events, enrich where user exists
#event_simpleName=ProcessRollup2
| join(
  subquery={...},
  field=User,
  include=[ComputerName, SourceIp],
  mode=left
)
```
- **Left join**: All main query events kept, enrichment added where match exists

### 5.3.3 Right Join
```cql
// Keep all auth events, show processes where they exist
#event_simpleName=UserLogon
| join(
  subquery={
    #event_simpleName=ProcessRollup2
    | groupBy([User], function=tail(1))
  },
  field=User,
  include=[ImageFileName, CommandLine],
  mode=right
)
```

### 5.3.4 Join Performance: The 200k Row Limit
```cql
// ⚠️ DANGEROUS: Subquery returns 500k users → SILENTLY TRUNCATES to 200k
#event_simpleName=ProcessRollup2
| join(
  subquery={
    #event_simpleName=UserLogon
    | groupBy([User], function=tail(1))  // 500k unique users
  },
  field=User
)

// ✅ SAFE: Use defineTable + match instead
defineTable(
  name="recent_users",
  query={
    #event_simpleName=UserLogon
    | groupBy([User], function=tail(1))
    | select([User, ComputerName, SourceIp])
  }
)
#event_simpleName=ProcessRollup2
| match(table="recent_users", field=User, include=[ComputerName, SourceIp], strict=false)
```
- **Hard limit**: 200,000 rows from subquery — **no error, silent truncation**
- **Sequential execution**: Main query waits for subquery
- **Use `defineTable()` + `match()`** for production enrichment

**Official ref**: [join() Function](https://library.humio.com/data-analysis/functions-join.html), [Query Joins: Ad-Hoc Tables](https://library.humio.com/data-analysis/query-joins-methods-adhoc-tables.html)

---

## 5.4 `selfJoin()` — High-Cardinality Self-Join

### 5.4.1 `selfJoinFilter()`
```cql
// Parent-child process correlation (optimized)
#event_simpleName=ProcessRollup2
| selfJoinFilter(
  field=ProcessId,
  where=[
    { #event_simpleName=ProcessRollup2 | ParentProcessId=* },  // Parent events
    { #event_simpleName=ProcessRollup2 | ImageFileName="powershell.exe" }  // Child events
  ],
  include=[ImageFileName, CommandLine, User, ParentProcessId, ComputerName, @timestamp]
)
// Result: child events enriched with parent fields (prefixed with _join_)
```

### 5.4.2 When to Use `selfJoin()`
- **High cardinality**: ProcessId, SessionId, CorrelationId
- **Parent-child**: Process tree analysis
- **Sessionization**: Link events by session ID
- **No 200k limit** (within memory)
- **Filter-first**: Each `where` element is a filter pipeline — reduces data before join

**Official ref**: [selfJoin() Function](https://library.humio.com/data-analysis/functions-selfjoin.html), [selfJoinFilter()](https://library.humio.com/data-analysis/functions-selfjoinfilter.html)

---

## 5.5 Ad-Hoc Tables: `defineTable()` + `match()`

### 5.5.1 `defineTable()` Syntax
```cql
// Create ad-hoc table (runs in parallel with main query)
defineTable(
  name="asset_inventory",
  query={
    #repo=assets
    #event_simpleName=AssetInventory
    | select([ip, hostname, owner, department, criticality])
  }
)

// Use in same or different query
#event_simpleName=NetworkConnectIP4
| match(table="asset_inventory", field=RemoteAddressIP4, column="ip", include=[hostname, owner, department], strict=false)
```

### 5.5.2 `match()` Syntax
```cql
// Basic match
match(table="asset_inventory", field=src_ip, column="ip", include=[owner, department])

// Left join (keep unmatched)
match(table="asset_inventory", field=src_ip, column="ip", include=[owner], strict=false)

// Multiple columns
match(file="indicators.csv", column="ioc", field=FileHash, include=["threat_name", "severity", "tags"])
```

### 5.5.3 `defineTable()` vs `join()`: Decision Guide

| Scenario | Use |
|----------|-----|
| Reference set < 200k rows, one-time query | `join()` OK |
| Reference set > 200k rows | `defineTable()` + `match()` **required** |
| Reference set reused across queries | `defineTable()` (define once, use many) |
| Multi-cluster views | `defineTable()` + `match()` only |
| Static CSV/JSON file | `readFile()` + `match()` or `defineTable()` |
| Need parallel execution | `defineTable()` + `match()` |
| Right join semantics needed | `join(mode=right)` |

**LogScale recommends `defineTable()` + `match()` over `join()`** for production use.

**Official ref**: [defineTable()](https://library.humio.com/data-analysis/functions-definetable.html), [match()](https://library.humio.com/data-analysis/functions-match.html), [Query Joins](https://library.humio.com/data-analysis/query-joins-methods-adhoc-tables.html)

---

## 5.6 Lookup Files: `readFile()` + `match()`

### 5.6.1 CSV Lookup Files
```cql
// Upload CSV via UI (Files) or API
// File: indicators.csv
// Columns: ioc, threat_name, severity, tags, source

// Enrich events
#event_simpleName=ProcessRollup2
| match(file="indicators.csv", column="ioc", field=FileHash, include=["threat_name", "severity", "tags"], strict=false)
```

### 5.6.2 Enrichment Patterns
```cql
// IP reputation
match(file="ip_reputation.csv", column="ip", field=src_ip, include=["reputation", "category", "last_seen"])

// User risk scoring
match(file="user_risk.csv", column="user", field=User, include=["risk_score", "watchlist"], strict=false)

// Asset criticality
match(file="assets.csv", column="hostname", field=ComputerName, include=["criticality", "environment", "owner"], strict=false)
```

**Best practice**: Keep lookup files under 1M rows. Update via scheduled automation (API).

---

## 5.7 Correlation Patterns

### 5.7.1 Process Tree (Parent-Child)
```cql
// Full process tree for a host
#event_simpleName=ProcessRollup2
| ComputerName="WKS01"
| selfJoinFilter(
  field=ProcessId,
  where=[
    { #event_simpleName=ProcessRollup2 | ParentProcessId=* },
    { #event_simpleName=ProcessRollup2 }
  ],
  include=[ImageFileName, CommandLine, User, ParentProcessId, @timestamp]
)
| sort(@timestamp)
| select([@timestamp, ImageFileName, CommandLine, User, ParentProcessId, _join_ImageFileName, _join_CommandLine])
```

### 5.7.2 Session Reconstruction
```cql
// Link auth + process + network by session
defineTable(
  name="user_sessions",
  query={
    #event_simpleName=UserLogon
    | select([User, ComputerName, SourceIp, SessionId, @timestamp])
  }
)

#event_simpleName=ProcessRollup2
| match(table="user_sessions", field=[User, ComputerName], column=[User, ComputerName], include=[SessionId, SourceIp], strict=false)
| // Now enrich network events
| match(table="user_sessions", field=[User, ComputerName], column=[User, ComputerName], include=[SessionId], strict=false)
```

### 5.7.3 Lateral Movement
```cql
// SMB/PSExec lateral movement
#event_simpleName=NetworkConnectIP4
| RemotePort=in([445, 135, 139])
| not(cidr(RemoteAddressIP4, subnet=["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]))

// Enrich with process creating connection
| defineTable(
    name="process_network",
    query={
      #event_simpleName=ProcessRollup2
      | select([ProcessId, ImageFileName, CommandLine, User, ComputerName])
    }
  )
| // Requires correlation via ProcessId - use selfJoin if available
```

---

## 5.8 Multi-Cluster Views

LogScale **multi-cluster views** allow querying across clusters. `defineTable()` + `match()` works across clusters; `join()` does **not**.

```cql
// defineTable works in multi-cluster views
defineTable(
  name="global_assets",
  query={
    #repo=global_assets
    | select([ip, hostname, region])
  }
)

// In any cluster's query
#event_simpleName=NetworkConnectIP4
| match(table="global_assets", field=RemoteAddressIP4, column="ip", include=[hostname, region], strict=false)
```

---

## 5.9 What's Next

- **Chapter 6**: Dashboards and visualization
- **Chapter 7**: Performance optimization and reference tables

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 6 — Dashboards, Widgets & Visualization

---

## 6.1 Dashboard Creation Workflow

1. **Define questions** — What decisions will this dashboard support?
2. **Design queries** — One query per widget, optimized for dashboard refresh
3. **Create dashboard** — UI: Dashboards → New Dashboard
4. **Add widgets** — Choose type per data (timeChart → Time Chart, groupBy → Table/Bar)
5. **Add parameters** — Time range, repository, filter dropdowns
6. **Set refresh** — Live (30s-5m) or scheduled
7. **Share** — Role-based access, public links, scheduled PDF reports

---

## 6.2 Dashboard Layout & Time Controls

- **Time range selector**: Global (top-right) or per-widget override
- **Parameters**: `${parameter_name}` in queries, rendered as dropdowns/text inputs
- **Layout**: Drag-drop grid, resize widgets
- **Sections**: Group widgets with headers

```cql
// Parameterized query example
#event_simpleName=ProcessRollup2
| ComputerName=${computer_name}
| ImageFileName=${process_name}
| timeChart(span=${span}, function=count())
```

---

## 6.3 Widget Types Reference

### 6.3.1 Time Chart 📈
- **Query**: `timeChart(span=1h, function=count(), series=field)`
- **Use for**: Trends over time, multiple series comparison
- **Options**: Line/area/bar, stacking, legend, Y-axis scale

### 6.3.2 Bar / Column Chart 📊
- **Query**: `groupBy([field], function=count()) | sort(_count, order=desc) | head(20)`
- **Use for**: Top N categories, distribution
- **Options**: Horizontal/vertical, stacking, value labels

### 6.3.3 Pie Chart 🥧
- **Query**: `groupBy([field], function=count()) | head(10)`
- **Use for**: Proportions (max 10 slices)
- **Options**: Donut, labels, legend

### 6.3.4 Table 📋
- **Query**: `table([fields], limit=100)` or `groupBy(...) | table([fields])`
- **Use for**: Detailed event lists, aggregated results
- **Options**: Column formatting, sorting, pagination, drill-down

### 6.3.5 Single Value 🔢
- **Query**: `groupBy([], function=count())` or `count()`
- **Use for**: KPIs, totals, current status
- **Options**: Trend comparison, thresholds, colors, sparkline

### 6.3.6 Gauge 📐
- **Query**: Single numeric value
- **Use for**: Metrics with thresholds (CPU%, disk%, error rate)
- **Options**: Min/max, bands (green/yellow/red), needle/mark

### 6.3.7 Sankey 🔗
- **Query**: `groupBy([source, target], function=sum(weight))`
- **Use for**: Flow analysis (process tree, network paths, user journeys)
- **Options**: Node colors, link opacity, labels

### 6.3.8 World Map 🌍
- **Query**: `ipLocation(ip, as=geo) | groupBy([geo.country], function=count())`
- **Use for**: Geographic distribution
- **Options**: Projection, color scale, tooltips

### 6.3.9 Heat Map 🔥
- **Query**: `bucket(span=1h, function=count(), by=[field1, field2])`
- **Use for**: Density over time × category
- **Options**: Color scale, cell labels

### 6.3.10 Event List 📄
- **Query**: `select([@timestamp, field1, field2]) | sort(@timestamp, order=desc) | head(100)`
- **Use for**: Raw event inspection, drill-down from other widgets
- **Options**: Column selection, `@rawstring` expand, highlighting

### 6.3.11 Text / Markdown 📝
- **Content**: Static markdown, documentation, runbooks
- **Use for**: Context, instructions, links to playbooks

---

## 6.4 Widget Configuration

| Setting | Description |
|---------|-------------|
| **Title** | Descriptive name |
| **Description** | Hover tooltip |
| **Query** | CQL query (parameterized) |
| **Time range** | Widget-specific or global |
| **Refresh** | Live interval or manual |
| **Visualization options** | Per-widget-type (colors, axes, labels) |
| **Drill-down** | Click → filter other widgets or open query |

---

## 6.5 Dashboard Filters & Parameters

```cql
// Parameter syntax: ${parameter_name}
// In UI: Parameters tab → add parameter
// Types: Text, Dropdown (static or query-based), Time Range, Repository

// Example: Dropdown populated from query
// Parameter: computer_name
// Query for dropdown:
#event_simpleName=ProcessRollup2
| groupBy([ComputerName], function=count())
| sort(_count, order=desc)
| head(100)
| select([ComputerName])

// In widget query:
#event_simpleName=ProcessRollup2
| ComputerName=${computer_name}
| timeChart(span=1h, function=count())
```

---

## 6.6 Sharing & Scheduled Reports

- **Role-based access**: Assign dashboard to roles
- **Public links**: Time-limited, read-only
- **Scheduled PDF reports**: Daily/weekly/monthly, email delivery
- **Embed**: iframe embedding (with auth)

---

## 6.7 Export Options

- **CSV**: From Table/Event List widgets
- **JSON**: Via API
- **PDF**: Scheduled reports or manual export
- **Query results**: API `/queryjobs` endpoint

---

## 6.8 Dashboard Best Practices

1. **One question per dashboard** — Focused dashboards load faster
2. **Parameterize everything** — Time range, host, user, process
3. **Use `timeChart()` for time widgets** — Optimized for dashboards
4. **Limit widget queries** — `head(20)` for bars, `limit=100` for tables
5. **Set appropriate refresh** — Live for SOC (30s-1m), scheduled for exec (daily)
6. **Name widgets clearly** — "Top 10 Processes by Count" not "Chart 1"
7. **Document in Text widget** — Data source, refresh, owner, links

---

## 6.9 What's Next

- **Chapter 7**: Performance optimization and reference tables

---

⬆️ [Back to Top](#quick-navigation)

---

# Chapter 7 — Performance, Optimization & Reference

---

## 7.1 How LogScale Stores Data: Segment Files

LogScale writes events to **segment files** (compressed, columnar, time-partitioned).

```
Segment File Structure:
┌─────────────────────────────────────────────────────┐
│  Header: schema, time range, row count, bloom filters│
├─────────────────────────────────────────────────────┤
│  Column: @timestamp (compressed, sorted)           │
│  Column: @rawstring (compressed, dictionary encoded)│
│  Column: #repo (tagged, bloom filter)              │
│  Column: #type (tagged, bloom filter)              │
│  Column: #event_simpleName (tagged, bloom filter)  │
│  Column: host, source, ... (standard fields)       │
│  Column: ImageFileName, CommandLine, ... (parser)  │
└─────────────────────────────────────────────────────┘
```

**Key properties**:
- **Time-sorted**: `@timestamp` is primary sort key
- **Columnar**: Only read columns needed
- **Compressed**: Dictionary encoding, delta encoding for time
- **Bloom filters**: On tagged fields for fast segment elimination

---

## 7.2 Tagged Fields: The Index Advantage

```cql
// Tag filter: checks bloom filter → eliminates segments → reads only matching
#event_simpleName=ProcessRollup2
// Scans ~1% of segments vs 100% for non-tagged field

// Non-tagged field: reads all segments in time range
ImageFileName="powershell.exe"
// Scans 100% of segments in time range
```

**Performance difference**: 10x-1000x faster for tag filters.

---

## 7.3 Query Execution Model

```
Query → Parser → Optimizer → Executor
           │
           ▼
    ┌─────────────────┐
    │ Segment Pruning │  (tag filters, time range)
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Column Reading  │  (only needed columns)
    └────────┬────────┘
             │
             ▼
    ┌─────────────────┐
    │ Pipeline Exec   │  (filter → transform → aggregate)
    └────────┬────────┘
             │
             ▼
         Results
```

**Pipeline execution**: Streaming where possible, materialization at aggregation.

---

## 7.4 Cardinality Management

### 7.4.1 Always Use `limit=` in `groupBy()`
```cql
// ❌ DANGEROUS: No limit → OOM on high cardinality
groupBy([User], function=count())

// ✅ SAFE: Limit prevents unbounded memory
groupBy([User], function=count(), limit=10000)

// ✅ SAFE: limit=max only for known small cardinality
groupBy([action], function=count(), limit=max)  // action has ~10 values
```

### 7.4.2 `limit=max` Only When Necessary
```cql
// Known low cardinality
groupBy([event_platform], function=count(), limit=max)  // Win/Lin/Mac only

// Unknown or high cardinality
groupBy([User], function=count(), limit=10000)
groupBy([FileHash], function=count(), limit=50000)
```

### 7.4.3 Filter Before Transform
```cql
// ❌ SLOW: Transform 1M events, then filter
#event_simpleName=ProcessRollup2
| fileName := lower(ImageFileName)
| fileName="powershell.exe"
| groupBy([ComputerName], function=count())

// ✅ FAST: Filter first (tag + field), then transform
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
| fileName := lower(ImageFileName)
| groupBy([ComputerName], function=count(), limit=10000)
```

---

## 7.5 Statement Ordering Performance

| Order | Query | Why |
|-------|-------|-----|
| ❌ | `groupBy` → `filter` | Aggregates all, then filters |
| ✅ | `filter` → `groupBy` | Reduces cardinality before aggregation |
| ❌ | `sort` → `filter` | Sorts full dataset |
| ✅ | `filter` → `sort` | Sorts reduced dataset |
| ❌ | `timeChart` → `filter` | Charts all time buckets |
| ✅ | `filter` → `timeChart` | Charts filtered data only |
| ❌ | `ipLocation` → `filter` | GeoIP on all events |
| ✅ | `filter` → `ipLocation` | GeoIP on <10K events |

---

## 7.6 Time Range Optimization

```cql
// ❌ SLOW: Default time range (often 24h or 7d)
#event_simpleName=ProcessRollup2

// ✅ FAST: Explicit narrow time range
#event_simpleName=ProcessRollup2
// In UI: Set time range to "Last 1 hour"
// In API: start=2026-09-23T10:00:00Z end=2026-09-23T11:00:00Z

// ✅ FAST: Relative time in query (if supported)
#event_simpleName=ProcessRollup2
// Time range set in query context
```

**Smaller time range = fewer segments = faster query**.

---

## 7.7 `join()` vs `selfJoin()` vs `defineTable()` Performance

| Method | Max Rows | Execution | Memory | Use Case |
|--------|----------|-----------|--------|----------|
| `join()` | 200k (hard) | Sequential | Medium | Small ref sets (<50k) |
| `selfJoin()` | Memory | Filter-first parallel | High | Parent-child, high cardinality |
| `defineTable()` + `match()` | No limit | Parallel | Configurable | **Production enrichment** |

**Recommendation**: Default to `defineTable()` + `match()` for all enrichment. Use `selfJoin()` for sessionization/parent-child. Avoid `join()` in production.

---

## 7.8 Live vs Scheduled Query Performance

| Aspect | Live Query | Scheduled Query |
|--------|------------|-----------------|
| **Refresh** | 30s-5m | Cron schedule |
| **Time range** | Rolling window | Fixed window |
| **Results** | Streamed | Materialized |
| **Use case** | SOC dashboards, real-time alerting | Reports, daily summaries |
| **Optimization** | Narrow time range, `limit=` | Can use wider ranges, pre-aggregate |

---

## 7.9 Query Debugging

```cql
// Inspect intermediate results
#event_simpleName=ProcessRollup2
| ImageFileName="powershell.exe"
| // Add this to see rows at this point
| select([@timestamp, ComputerName, ImageFileName, CommandLine])
| head(10)

// Count events at each stage
#event_simpleName=ProcessRollup2
| count(as=stage1)
| ImageFileName="powershell.exe"
| count(as=stage2)
| test(match(CommandLine, "(?i)encoded"))
| count(as=stage3)
// Returns: stage1, stage2, stage3 counts
```

**UI Tools**: Query Jobs panel shows execution time, rows scanned, segments read, memory used.

---

## 7.10 Optimization Checklist

- [ ] Tag filters first (`#event_simpleName=`, `#repo=`)
- [ ] Explicit narrow time range
- [ ] Field filters before complex filters (`in`, `test`, `cidr`)
- [ ] `limit=` on every `groupBy()`, `collect()`, `top()`
- [ ] `defineTable()` + `match()` for enrichment (not `join()`)
- [ ] Filter before enrichment (`ipLocation`, `asn`, `rdns`)
- [ ] Filter before transform (`:=`, `format`, `regex`)
- [ ] `select()` instead of `table()` for event lists (no aggregation)
- [ ] `timeChart()` for dashboard time series (not `bucket()` + `sort`)
- [ ] Test with Job Inspector: segments read, rows processed, memory, time

---

## 7.11 Reference: Decision Tables & Cheat Sheets

### 7.11.1 Filter Function Decision Table

| Need | Function | Example |
|------|----------|---------|
| Tagged field exact | `#tag=value` | `#event_simpleName=ProcessRollup2` |
| Tagged field prefix | `#tag=prefix*` | `#event_simpleName=Process*` |
| Field exact | `field=value` | `ImageFileName="powershell.exe"` |
| Field prefix | `field=prefix*` | `ImageFileName="power*"` |
| Multiple values (OR) | `in(field, values=[...])` | `ImageFileName=in(["ps.exe","pwsh.exe"])` |
| Field comparison | `test(field1 > field2)` | `test(bytes_out > bytes_in)` |
| Complex boolean | `test((A AND B) OR C)` | `test((user="admin" AND src_ip!="10/8") OR fail>5)` |
| IP in range | `cidr(ip, subnet=[...])` | `cidr(src_ip, ["10.0.0.0/8"])` |
| Regex match | `test(match(field, "regex"))` | `test(match(cmd, "(?i)enc"))` |
| Field exists | `test(field=X)` | `test(field=ParentProcessId)` |
| Field missing | `test(not(field=X))` | `test(not(field=User))` |

### 7.11.2 Aggregation Function Quick Reference

| Need | Function | Example |
|------|----------|---------|
| Count events | `count()` | `groupBy([host], function=count())` |
| Sum field | `sum(field=X)` | `sum(bytes)` |
| Average field | `avg(field=X)` | `avg(bytes)` |
| Min/Max field | `min(field=X)` / `max(field=X)` | `min(@timestamp)` |
| Collect values | `collect(field=X, limit=N)` | `collect(ImageFileName, limit=100)` |
| Multiple aggs | `function=[count(), sum(X)]` | `function=[count(), sum(bytes)]` |
| Time buckets | `bucket(span=1h, function=...)` | `bucket(span=1h, function=count())` |
| Time chart | `timeChart(span=1h, function=...)` | `timeChart(span=1h, function=count(), series=host)` |
| Top N | `top(N, field=X)` | `groupBy([f], function=count()) | top(10, field=_count)` |
| Distinct count | `dc(field=X, as=Y)` | `dc(User, as=unique_users)` |

### 7.11.3 Join Method Decision Guide

| Scenario | Recommended |
|----------|-------------|
| Reference set < 50k, one-off | `join()` |
| Reference set > 50k | `defineTable()` + `match()` |
| Reference set reused | `defineTable()` + `match()` |
| Multi-cluster view | `defineTable()` + `match()` |
| Parent-child (ProcessId) | `selfJoinFilter()` |
| Sessionization (SessionId) | `selfJoinFilter()` |
| Static CSV file | `readFile()` + `match()` |
| Right join needed | `join(mode=right)` |

### 7.11.4 CQL vs SPL Syntax Cheat Sheet

| Operation | CQL | SPL |
|-----------|-----|-----|
| Field assignment | `x := y + 1` | `eval x=y+1` |
| Concat | `a + " " + b` / `concat(a," ",b)` | `a." ".b` |
| Rename | `rename(old, as=new)` | `rename old AS new` |
| Group + count | `groupBy([f], function=count())` | `stats count by f` |
| Time bucket | `bucket(span=1h, function=count())` | `bin span=1h \| stats count` |
| Time chart | `timeChart(span=1h, function=count())` | `timechart span=1h count` |
| Tag filter | `#tag=value` | N/A |
| Field filter | `field=value` | `field=value` |
| In (OR) | `in(field, values=[...])` | `field IN (...)` |
| Regex extract | `regex("(?<f>...)", field=@rawstring)` | `rex field=_raw "(?<f>...)"` |
| Regex filter | `test(match(field, "regex"))` | `regex field="regex"` |
| Lookup enrich | `match(file="x.csv", column="c", field=f)` | `lookup x.csv c AS f` |
| Join | `join(subquery={...}, field=f)` | `join f [ search ... ]` |
| Table output | `table([fields], limit=N)` | `table fields` |
| Select fields | `select([fields])` | `fields f1, f2` |
| Sort | `sort(field, order=desc)` | `sort -field` |
| Head | `head(N)` | `head N` |
| Format time | `formatTime("%Y-%m-%d", field=@timestamp)` | `strftime(_time, "%Y-%m-%d")` |

### 7.11.5 Statement Ordering Cheat Sheet

```
1. TAG FILTERS          #event_simpleName=X #repo=Y
2. FIELD FILTERS        field="value" field="prefix*"
3. COMPLEX FILTERS      in(), test(), cidr(), match()
4. TRANSFORMATIONS      :=, format(), concat(), split(), lower(), replace()
5. ENRICHMENT           ipLocation(), asn(), rdns(), match(), join()
6. AGGREGATION          groupBy(), bucket(), timeChart(), stats(), collect()
7. POST-PROCESSING      sort(), head(), tail(), table(), select(), rename(), drop()
```

### 7.11.6 Common Mistakes & Anti-Patterns

| Mistake | Problem | Fix |
|---------|---------|-----|
| No `limit=` on `groupBy()` | OOM on high cardinality | Always `limit=10000` (or appropriate) |
| `join()` for enrichment | 200k silent truncation | `defineTable()` + `match()` |
| `ipLocation()` on full dataset | Timeout, slow | Filter to <10K events first |
| `sort()` before `filter()` | Sorts all data | Filter first |
| `table()` for event list | Aggregates (loses events) | Use `select()` |
| No time range | Scans all data | Set explicit time range |
| `field=*` for existence | Slow (full scan) | `test(field=X)` |
| `regex()` without named groups | No fields created | Use `(?<name>...)` |
| `cidr()` with huge subnet list | Slow | Use `defineTable()` for large CIDR lists |

### 7.11.7 Glossary

| Term | Definition |
|------|------------|
| **Event** | Single record with `@timestamp`, `@rawstring`, fields |
| **Repository** | Physical storage container with retention/access |
| **View** | Logical subset of repository(s) with optional field mapping |
| **Tagged Field** | Indexed field (`#tag`) with bloom filter for fast filtering |
| **Parser** | Ingestion-time transformation (regex, kvParse, JSON) |
| **CPS** | CrowdStrike Parsing Standard — normalized field names |
| **Segment File** | Compressed, columnar, time-partitioned storage unit |
| **Bloom Filter** | Probabilistic index for tagged fields |
| **Cardinality** | Number of unique values in a field |
| **Ad-Hoc Table** | `defineTable()` — named subquery for `match()` |
| **Live Query** | Continuously refreshing query (dashboard) |
| **Scheduled Query** | Runs on cron, materializes results |

### 7.11.8 File Inventory

```
chatgpt-cql/
├── README.md           # Overview, learning path, evidence standard
├── INDEX.md            # This file (table of contents)
├── SOURCES.md          # Official docs, community refs, evidence standard
├── CQL.md              # This comprehensive reference (all chapters)
├── labs/
│   ├── data/
│   │   ├── process_events.json      # Synthetic ProcessRollup2 events
│   │   ├── network_events.json      # Synthetic NetworkConnectIP4 events
│   │   ├── auth_events.json         # Synthetic UserLogon/Failed events
│   │   ├── dns_events.json          # Synthetic DnsRequest events
│   │   └── lookup_files/            # CSV files for match() practice
│   ├── 01-syntax-fundamentals/
│   │   └── README.md                # Lab: CQL vs SPL, field assignment, filtering
│   ├── 02-function-practice/
│   │   └── README.md                # Lab: groupBy, timeChart, ipLocation, match
│   ├── 03-threat-hunting/
│   │   └── README.md                # Lab: Brute force, beaconing, process chains
│   └── 04-dashboards/
│       └── README.md                # Lab: Widget creation, parameters, sharing
```

### 7.11.9 Version History

| Version | Date | Changes |
|---------|------|---------|
| 1.0 | 2026-11-19 | Initial release: 7 chapters, 3.8 function lookup, MITRE mapping, labs structure |

### 7.11.10 Contributing

This is a living reference. Contributions welcome for:

- New CQL functions/features (LogScale updates)
- Corrections to function classifications
- Additional threat hunting patterns
- Performance benchmarks
- Lab exercises with synthetic data

**Requirements**:
1. Provide reproducible example with `createEvents()`
2. Identify LogScale version
3. Show expected output
4. Cite official LogScale documentation

---

## Labs (Hands-On Practice)

This repository includes synthetic datasets for hands-on validation:

```
labs/
├── data/
│   ├── process_events.json      # Synthetic ProcessRollup2 events
│   ├── network_events.json      # Synthetic NetworkConnectIP4 events
│   ├── auth_events.json         # Synthetic UserLogon/Failed events
│   ├── dns_events.json          # Synthetic DnsRequest events
│   └── lookup_files/
│       ├── indicators.csv       # FileHash, threat_name, severity
│       ├── assets.csv           # ip, hostname, owner, department
│       └── ip_reputation.csv    # ip, reputation, category
├── 01-syntax-fundamentals/
│   └── README.md                # Lab: CQL vs SPL, field assignment, filtering
├── 02-function-practice/
│   └── README.md                # Lab: groupBy, timeChart, ipLocation, match
├── 03-threat-hunting/
│   └── README.md                # Lab: Brute force, beaconing, process chains
└── 04-dashboards/
    └── README.md                # Lab: Widget creation, parameters, sharing
```

**To use labs:**
1. Import `labs/data/*.json` into a test LogScale repository (via API or UI)
2. Import `labs/data/lookup_files/*.csv` via Files UI
3. Run examples from each lab after adjusting repository name
4. Compare result counts and fields
5. Inspect query performance in LogScale UI (Query Jobs)
6. Adapt to your own lab only after validating expected output

---

⬆️ [Back to Top](#quick-navigation)

---

*End of CQL Complete Reference v1.0*
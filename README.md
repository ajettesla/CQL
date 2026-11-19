# CrowdStrike Query Language (CQL) Learning Repository — v1

A structured, source-backed learning repository for CrowdStrike Query Language (CQL) used in Falcon LogScale (formerly Humio), covering query syntax, functions, optimization, threat hunting patterns, and dashboard creation.

**Version:** 1.0  
**Research baseline:** 19 November 2026  
**Status:** Learning repository; examples must be validated against the LogScale product version in use.

## What this repository is trying to teach

This repository is organized around how LogScale actually processes queries—not merely around a list of functions.

You will learn:

1. How LogScale stores events, repositories, views, and tagged fields.
2. How to write efficient queries using the pipe (`|`) operator and filter-first methodology.
3. Why CQL differs from Splunk SPL, and the critical syntax differences.
4. How functions are classified: filtering, transformation, aggregation, parsing, enrichment, and visualization.
5. Why statement ordering (tag filters → field filters → transformations → aggregations → post-processing) affects performance.
6. How to extract, transform, aggregate, correlate, and visualize events.
7. How joins, lookups, and ad-hoc tables work for multi-event correlation.
8. How threat hunting queries map to MITRE ATT&CK techniques.
9. How dashboards and widgets are created and shared.

## Start here

Read these in order:

1. [Index and learning path](INDEX.md)
2. [Event model: repositories, tagged fields, and metadata](docs/00-foundations/01-event-model.md)
3. [CQL syntax fundamentals](docs/00-foundations/02-cql-syntax.md)
4. [Query execution and optimization](docs/00-foundations/03-query-execution.md)
5. [Critical syntax differences: CQL vs SPL](docs/00-foundations/04-cql-vs-spl.md)

Then continue through query writing, functions, threat hunting, joins, and dashboards.

## Repository structure

```text
.
├── README.md
├── INDEX.md
├── ROADMAP.md
├── CONTRIBUTING.md
├── SOURCES.md
├── docs/
│   ├── 00-foundations/
│   ├── 01-query-writing/
│   ├── 02-functions/
│   ├── 03-threat-hunting/
│   ├── 04-joins-lookups/
│   ├── 05-dashboards/
│   └── 06-reference/
└── labs/
    ├── data/
    ├── 01-syntax-fundamentals/
    ├── 02-function-practice/
    ├── 03-threat-hunting/
    └── 04-dashboards/
```

## CQL is not SPL — taught separately on purpose

CQL and SPL share pipe-based syntax, but the semantics, function names, and execution models differ significantly.

| Aspect | CQL (LogScale) | SPL (Splunk) |
|---|---|---|
| Field assignment | `newField := value` | `eval newField=value` |
| String concat | `field1 + " " + field2` | `field1." ".field2` |
| Rename fields | `rename(old, as=new)` | `rename old AS new` |
| Aggregation | `groupBy(field, function=count())` | `stats count by field` |
| Tagged fields | `#tag=value` (indexed, fastest) | No direct equivalent |
| Time syntax | `@timestamp` (built-in) | `_time` |

Do not mechanically translate SPL queries to CQL. Learn the CQL patterns natively.

Official reference: [CrowdStrike Query Language](https://library.humio.com/data-analysis/crowdstrike-query-language.html)

## Evidence standard

Every substantial tutorial should include:

- the product and version (LogScale Cloud / Self-Hosted, version);
- a small input example (using `createEvents()` or sample data);
- the exact query;
- the expected result;
- why each function/operator is used;
- a note about execution behavior or performance when relevant;
- an official LogScale documentation reference;
- a community or CrowdStrike reference only when it adds practical context.

Official documentation is the authority for supported syntax and product behavior. Community examples and GitHub repositories are useful for learning patterns, but they must not override current product documentation.

## A note about function classifications

LogScale functions can be grouped by their role in a query pipeline:

1. **Filtering** — reduce events early: tag filters (`#tag`), field filters (`field=value`), `in()`, `test()`, `cidr()`
2. **Transformation** — create/modify fields: `:=`, `format()`, `regex()`, `split()`, `lower()`, `upper()`, `concat()`
3. **Aggregation** — summarize: `groupBy()`, `count()`, `sum()`, `avg()`, `stats()`, `collect()`, `top()`, `bucket()`, `timeChart()`
4. **Parsing** — extract structure: `parseJson()`, `kvParse()`, `splitString()`, `regex()` (with named groups)
5. **Enrichment** — add context: `ipLocation()`, `asn()`, `cidr()`, `rdns()`, `geoHash()`, `match()`, `join()`, `readFile()`
6. **Visualization** — shape output: `table()`, `select()`, `rename()`, `drop()`, `sort()`, `head()`, `tail()`, `formatTime()`

These categories are **not mutually exclusive**. A function's behavior can depend on its position, arguments, and options. For example, `regex()` extracts fields (parsing) when used with named groups but filters (filtering) when used as a boolean test.

## How to use the labs

The repository includes synthetic datasets in `labs/data/` (JSON/CSV). They contain no real user, host, or production data.

You can:

1. Import the data into a test LogScale repository (via API or UI);
2. Run the CQL examples after changing the repository name;
3. Compare the result count and fields;
4. Inspect query performance in the LogScale UI;
5. Adapt the same logic to your own lab only after validating the expected output.

## Scope and limitations

This is an independent community learning project. It is not an official CrowdStrike manual, and it does not claim that every function or option is supported in every LogScale release.

Some topics are deliberately split because the same concept (e.g., "joins") has different performance characteristics and syntax options in different contexts (live query vs. scheduled search vs. dashboard).

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: provide a reproducible example, identify the LogScale version, show expected output, and cite the source that supports the claim.

## Sources

The [source register](SOURCES.md) distinguishes official references, CrowdStrike Community discussions, the CrowdStrike logscale-community-content GitHub repository, and selected blog articles.
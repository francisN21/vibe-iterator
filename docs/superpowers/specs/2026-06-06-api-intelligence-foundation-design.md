# API Intelligence Foundation Design

## Goal

Make Vibe Iterator a stronger one-stop runtime security tool for vibe-coded apps by introducing a shared API intelligence layer. The layer should discover the real API attack surface, preserve structured endpoint evidence, find likely hidden parameters, show the inventory in results, and feed richer targets into existing scanners.

This phase covers:

- endpoint inventory model
- method-aware discovery
- hidden parameter discovery
- API inventory reporting in dashboard/results
- scanner integration so existing scanners test inventory endpoints, not only raw network requests

## Current State

Vibe Iterator already has useful pieces:

- `discover` stage runs sitemap, DOM crawl, JavaScript route extraction, and API endpoint harvesting.
- `DiscoveryResult` stores `pages`, string-based `api_endpoints`, and `discovered_at`.
- results/history serialize `discovered_surface`.
- dashboard results render discovered pages and endpoint strings.
- scanners consume `listeners["network"].get_requests()` and each scanner performs its own endpoint filtering.

The missing contract is a rich, shared API inventory. Today endpoint knowledge is mostly string-based, so scanners repeatedly rediscover paths and can miss method variants, body parameters, hidden parameters, and discovered-but-not-observed endpoints.

## Discovery Mode Policy

Discovery must be safe by default on public targets and more complete on local developer targets.

### Default Mode

Add `api_intelligence.mode` with these values:

- `auto`
- `safe`
- `aggressive`
- `off`

Default is `auto`.

In `auto`:

- Public domain targets use `safe`.
- Local targets use `aggressive`.

Local targets include:

- `localhost`
- `127.0.0.1`
- `::1`
- RFC1918/private IP ranges such as `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`
- `.local` hostnames

Users can always override `auto` with `safe`, `aggressive`, or `off`.

### Safe Mode

Safe mode should be appropriate for production domains:

- build inventory from browser traffic, discovered pages, sidecar endpoints, and documentation endpoints when they are already visible
- normalize methods, paths, query parameters, body shape, auth signal, response status, content type, and source evidence
- run bounded HEAD/GET/OPTIONS checks only when they do not mutate state
- run hidden parameter discovery only in passive or low-impact confirmation mode
- do not brute-force large route wordlists
- do not send state-changing method probes unless a scanner already has explicit proof rules and stage policy permits it

### Aggressive Mode

Aggressive mode is for localhost, staging, and explicitly authorized targets:

- method-aware route discovery with bounded wordlists
- OPTIONS and method matrix checks
- candidate API route expansion from framework conventions
- hidden query/body/header parameter probing
- schema/doc endpoint probing
- inventory diffing between observed, discovered, and probed endpoints

Aggressive mode must be bounded by config limits:

- max route candidates
- max methods per route
- max hidden parameters per endpoint
- per-request timeout
- global API intelligence timeout

### Warning Contract

When aggressive mode is selected or auto-resolved, the UI and CLI must show a warning before the run starts.

Warning should say:

- aggressive discovery sends extra HTTP requests beyond normal browsing
- it may trigger logs, rate limits, analytics events, emails, audit alerts, or WAF rules
- it should be used only on localhost, staging, or targets the user is authorized to test
- users can switch to safe mode for production domains

The user-facing control should be toggleable:

- `Auto`
- `Safe`
- `Aggressive`
- `Off`

The resolved mode should be visible in results.

## Inventory Model

Add a new `vibe_iterator/api_inventory.py` module, or a small `vibe_iterator/api/` package if implementation needs multiple files.

Core dataclasses:

```python
@dataclass
class ApiParameter:
    name: str
    location: str  # query, body, header, path, cookie
    observed_values: list[str]
    source: str  # observed, inferred, hidden_probe, schema
    confidence: str  # confirmed, inferred, needs_review
    sensitive_hint: bool = False


@dataclass
class ApiEndpoint:
    method: str
    url: str
    origin: str
    path: str
    normalized_path: str
    status_codes: list[int]
    content_types: list[str]
    request_content_types: list[str]
    auth_observed: bool
    response_auth_required_hint: bool
    parameters: list[ApiParameter]
    sources: list[str]  # network, discover_sidecar, route_wordlist, js_route, schema, docs
    risk_tags: list[str]  # auth, admin, upload, webhook, graphql, file, redirect, ssrf, state_changing
    confidence: str  # confirmed, inferred, needs_review


@dataclass
class ApiInventory:
    generated_at: str
    mode: str
    resolved_mode: str
    target: str
    endpoints: list[ApiEndpoint]
    summary: dict[str, int]
    warnings: list[str]
```

The old `DiscoveryResult.api_endpoints` string list remains for backward compatibility. A new field should hold the structured inventory:

```python
api_inventory: ApiInventory | None = None
```

Serialization must preserve both:

- old `api_endpoints` strings
- new structured `api_inventory`

## Method-Aware Discovery

Discovery should combine multiple sources:

- captured browser network requests
- sidecar endpoints from `vibe-iterator.discovered.yaml`
- crawler and JS-extracted routes
- framework-aware route patterns
- documentation endpoints such as OpenAPI/Swagger paths when publicly visible
- aggressive wordlist candidates when enabled

Normalize every endpoint by:

- method
- origin
- path
- normalized path with IDs collapsed to `{id}`
- query parameter names
- JSON body keys
- form body keys
- content type
- auth header/cookie presence
- status code set

Method-aware discovery should not treat `GET /api/users` and `POST /api/users` as one endpoint. It should store both and tag likely state-changing methods.

Aggressive route discovery should use small built-in wordlists first:

- common API prefixes: `/api`, `/api/v1`, `/v1`, `/v2`, `/graphql`, `/rest`, `/rpc`
- auth routes: `login`, `logout`, `signup`, `register`, `forgot-password`, `reset-password`, `verify`, `otp`, `magic-link`
- admin routes: `admin`, `users`, `roles`, `settings`, `billing`, `tenant`
- data routes from observed nouns and JS routes

Large external wordlists are out of scope for this foundation phase but the design should allow future pluggable wordlists.

## Hidden Parameter Discovery

Hidden parameter discovery should be modeled after Arjun but constrained for runtime safety.

Safe mode:

- infer likely hidden parameters from observed body/query/header names
- compare sibling endpoints for missing parameters
- parse API docs/schema only when already visible
- optionally send low-impact GET probes to endpoints already observed with GET

Aggressive mode:

- probe bounded hidden parameter candidates on eligible endpoints
- support query parameters and JSON body keys
- avoid destructive endpoints unless a scanner has explicit safe mutation controls
- record parameters as `source: hidden_probe`
- set `confidence: confirmed` only when the response changes in a meaningful, non-error way
- set `confidence: needs_review` for weak response diffs

Candidate parameter families:

- authorization: `role`, `admin`, `isAdmin`, `permissions`, `tenant_id`, `org_id`, `user_id`
- pagination/filtering: `limit`, `offset`, `page`, `sort`, `order`, `filter`, `q`
- include/expand: `include`, `expand`, `fields`, `select`
- redirects/URLs: `next`, `return_to`, `redirect`, `url`, `callback_url`
- files/uploads: `path`, `file`, `filename`, `content_type`
- debug: `debug`, `trace`, `verbose`

## Feeding Inventory Into Scanners

The runner should build or load `ApiInventory` before scanner execution and inject it into listeners:

```python
listeners = {
    "network": network,
    "console": console,
    "storage": storage,
    "api_inventory": api_inventory,
}
```

Scanners should migrate incrementally. Existing network-based behavior remains as fallback.

First scanners to consume inventory:

- `mass_assignment`: use hidden body/query parameters and state-changing endpoints
- `idor_check`: use normalized `{id}` paths and auth-observed endpoints
- `http_method_tampering`: use method matrix and observed method variants
- `rate_limit_check`: use auth-tagged POST endpoints
- `api_exposure`: use auth-observed API endpoints and structured response metadata
- `ssrf_check`: use URL-like hidden parameters
- `path_traversal_check`: use file/path hidden parameters
- `open_redirect_check`: use redirect-like hidden parameters
- `graphql_check`: use GraphQL-tagged endpoints

Each migrated scanner should add evidence fields that identify inventory source:

- `inventory_source`
- `inventory_confidence`
- `inventory_endpoint`
- `inventory_parameters_used`

## Reporting

Dashboard/results should show an API Inventory panel.

Minimum UI:

- resolved discovery mode
- endpoint count
- method counts
- auth-observed count
- hidden parameter count
- high-risk tag counts
- table/list of endpoints with method, path, source, confidence, and risk tags
- warning banner when aggressive mode was used

Existing discovery pages/endpoints panels can remain, but structured inventory should become the primary API surface view.

Exported reports and JSON history should include the inventory.

## Configuration

Add optional config:

```yaml
api_intelligence:
  mode: auto
  max_route_candidates: 200
  max_methods_per_route: 6
  max_hidden_params_per_endpoint: 20
  request_timeout_seconds: 3
  total_timeout_seconds: 45
  wordlists:
    routes: builtin
    params: builtin
```

If config is absent, defaults apply.

CLI/dashboard should expose the mode toggle. Advanced limits can stay config-only in this phase.

## Safety And False Positive Rules

- Public targets default to safe mode.
- Aggressive mode requires visible warning and explicit toggle unless auto-resolved for local targets.
- Findings should not report vulnerability solely because an endpoint exists.
- Hidden parameter findings must be reported by downstream scanners only when exploit proof exists.
- Inventory can mark `needs_review`, but scanners must not convert weak inventory signals into confirmed vulnerabilities without proof.
- Bounded probes should avoid known destructive parameter names unless the scanner has explicit safe controls.

## Testing Requirements

Unit tests:

- inventory normalization from network requests
- query, JSON body, form body, path, and header parameter extraction
- mode resolver: public domain -> safe, localhost/private IP/.local -> aggressive
- user override: safe/aggressive/off wins over auto
- serialization keeps old `api_endpoints` and new `api_inventory`
- sidecar round-trip with structured inventory
- hidden parameter candidate selection and dedupe

Integration tests:

- runner injects `api_inventory` into scanner listeners
- discover stage includes structured inventory in `discovered_surface`
- history serializer includes inventory
- dashboard result payload has inventory fields
- at least one scanner consumes inventory with network fallback preserved

Proof tests:

- vulnerable fixture includes endpoint families that only become scanner targets through inventory or hidden parameter discovery
- scanner reports include `inventory_source` evidence after migration
- safe mode avoids aggressive wordlist probes against public-style target
- aggressive mode probes bounded local candidates

Verification gates:

- targeted API inventory tests
- scanner tests for migrated scanners
- `python -m pytest -q`
- `python scripts/check_scanner_exposure.py`

## Non-Goals

- Full Schemathesis-equivalent schema fuzzing.
- Large external wordlist support.
- Full InQL-style GraphQL schema browser.
- APIClarity-level long-term traffic drift analytics.
- Replacing every scanner in one patch.

The foundation must make those future features easier without forcing them into this phase.

## Implementation Slices

1. Inventory model and mode resolver.
2. Inventory builder from captured network requests and sidecar strings.
3. Safe hidden parameter inference.
4. Aggressive bounded method-aware route and parameter probing.
5. Runner injection and discover result serialization.
6. Dashboard/results inventory panel and report export.
7. First scanner migrations: `mass_assignment`, `idor_check`, `api_exposure`, and `rate_limit_check`.
8. Follow-on scanner migrations for URL/file/redirect/GraphQL-focused scanners.

Each slice should be committed after targeted tests pass. Full-suite verification is required before declaring the goal complete.

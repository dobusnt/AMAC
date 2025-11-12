
# AMAC — API Mapper + Auth Checker (pentester-friendly)

**AMAC** helps ethical hackers quickly map API endpoints from OpenAPI/Swagger, probe **no-auth vs. authenticated** behavior (including multiple identities), and produce a tidy HTML report — all while respecting strict **scope safety rails**.

> ⚠️ **Authorized targets only.** You are solely responsible for ensuring you have permission. Use conservative scope, budgets, and rates.

---

## TL;DR

```bash
# 1) Install (editable mode)
py -m pip install -U pip
py -m pip install -e .

# 2) Run the local demo
python scripts/mock_api.py          # terminal A
scripts/demo_win.bat                # terminal B (Windows)
# or: pwsh -File scripts/demo_ps.ps1

# 3) Real target (OpenAPI mapping -> probe -> analyze -> report)
py -m amac map    --openapi <spec.json|yaml|URL> --scope examples/scope_advanced.yml --out out/endpoints.json
py -m amac probe  --endpoints out/endpoints.json --scope examples/scope_advanced.yml --auth <your_auth.yml> --identities all
py -m amac analyze --run-dir out/run_YYYY-MM-DD_HH-MM-SS
py -m amac report  --run-dir out/run_YYYY-MM-DD_HH-MM-SS
```

> **Note:** On Windows, if `amac` command is not found, use `py -m amac` instead. See [Installation](#install) for details.

---

## What it does (today)

* **OpenAPI → Endpoints (GET/HEAD):** handles server variables (`servers[].variables`), `$ref` for parameters, required path/query param sampling, inherited security.
* **Scope safety rails:**

  * Host **allow/deny** and **base URLs**
  * **Per-path allow/deny** (glob or `re:` patterns)
  * **Hard request budget** to stop over-scans
* **Probing & RBAC matrix:**

  * Sends **no-auth** + one or **all identities** (RBAC view)
  * Auth types: **Bearer/header**, **Basic**, **Cookie**, **OAuth2 (client-credentials, password)**, **form-login cookie capture**
  * One-shot **refresh** retry for OAuth2/form-login after 401
* **WAF-friendly pacing:** global + per-host concurrency caps, RPS limiter, jitter, bounded backoff, TLS/redirect controls.
* **Evidence hygiene:** header redaction (auth/cookie/api keys), response snippet privacy levels (`none|minimal|strict`).
* **Findings + HTML report:** conservative heuristics flag likely auth/enforcement issues; export JSON/Markdown + HTML.
* **Dry-run mode:** plan requests without sending traffic.
* **Windows-friendly:** mock server + demo scripts; works cross-platform.

---

## “Basic today” features (I'll iterate)

These work in a minimal form now; I plan to expand them:

* **OAuth2:** client-credentials & password only (no **PKCE** yet), no **mTLS**.
* **Methods:** **GET/HEAD only** (no safe POST payload sampler yet).
* **Heuristics:** intentionally **conservative** (favor low false positives).
* **Crawling:** no **auto-pagination** crawler yet.

> Want these sooner? Open an issue or PR — happy to collaborate.

---

## Install

### Requirements

* Python **3.10+** recommended (3.10–3.12 widely used; 3.13 also works; 3.14+ may require typer upgrade).
* Windows, macOS, or Linux

### Installation Steps

1. **Clone or download this repository:**
   ```bash
   cd AMAC
   ```

2. **Upgrade pip:**
   ```bash
   py -m pip install -U pip
   ```

3. **Install AMAC in editable mode:**
   ```bash
   py -m pip install -e .
   ```

4. **Verify installation:**
   ```bash
   py -m amac --version
   py -m amac --help
   ```

### Running AMAC

**On Windows:** If the `amac` command is not in your PATH, use:
```bash
py -m amac <command>
```

**On Linux/macOS:** You can use either:
```bash
amac <command>
# or
python -m amac <command>
```

> **Troubleshooting:** If you get "command not found", add Python's Scripts directory to your PATH, or always use `py -m amac` (Windows) or `python -m amac` (Linux/macOS).

---

## Quickstart (demo)

This demo uses a local mock API server to show how AMAC works without hitting real endpoints.

### Step 1: Start the Mock API Server

Open a terminal and run:
```bash
python scripts/mock_api.py
```

You should see:
```
Serving HTTP on 127.0.0.1 port 8000 ...
```

**Keep this terminal open!** The server must be running for the demo.

### Step 2: Run AMAC Demo

Open a **new terminal** (keep the mock server running) and run:

**Windows:**
```bash
scripts/demo_win.bat
# or
pwsh -File scripts/demo_ps.ps1
```

**Linux/macOS:**
```bash
bash scripts/demo.sh  # if it exists, or run commands manually
```

### Step 3: View Results

After the demo completes, you'll find:

* `out/local_endpoints.json` - Mapped endpoints from the mock API
* `out/run_demo/summary.json` - Summary of all probe results
* `out/run_demo/requests/*.json` - Individual request/response snapshots
* `out/run_demo/findings.json` - Security findings
* `out/run_demo/findings.md` - Findings in Markdown format
* `out/run_demo/report.html` - **Open this in your browser** for a visual report

### What the Demo Does

1. Maps endpoints from the mock API's OpenAPI spec
2. Probes each endpoint without authentication
3. Probes each endpoint with a Bearer token
4. Analyzes differences to find potential security issues
5. Generates a report

This demonstrates the full workflow without any risk!

---

## Real-world Usage (Step-by-Step)

### Prerequisites

Before running AMAC on a real target, you need:

1. **OpenAPI/Swagger specification** - JSON or YAML file, or a URL
2. **Scope configuration** (`scope.yml`) - Defines allowed hosts, paths, and rate limits
3. **Auth configuration** (`auth.yml`) - Defines authentication methods and credentials

### Step 1: Create Your Scope File

Create a `scope.yml` file to define what you're allowed to test. **Start conservative!**

See `examples/scope_advanced.yml` for a full example. Minimal example:

```yaml
allowed:
  - api.example.com
base_urls:
  - "https://api.example.com"
request_policy:
  safe_methods_only: true
  max_rps: 2
  hard_request_budget: 100  # Safety limit!
```

### Step 2: Create Your Auth File

Create an `auth.yml` file with your authentication credentials.

See examples:
- `examples/auth_demo.yml` - Bearer token
- `examples/auth_oauth2.yml` - OAuth2
- `examples/auth_form_login.yml` - Form-based login

### Step 3: Map Endpoints from OpenAPI

Extract endpoints from your OpenAPI specification:

```bash
py -m amac map \
  --openapi https://api.example.com/openapi.json \
  --scope scope.yml \
  --out out/endpoints.json
```

Or use a local file:
```bash
py -m amac map \
  --openapi openapi.json \
  --scope scope.yml \
  --out out/endpoints.json
```

**What this does:**
- Parses the OpenAPI spec
- Expands server variables and path parameters
- Filters endpoints based on your scope
- Saves to `endpoints.json`

### Step 4: Validate Your Setup (Optional but Recommended)

Check that everything is configured correctly:

```bash
py -m amac check \
  --endpoints out/endpoints.json \
  --scope scope.yml \
  --auth auth.yml
```

### Step 5: Dry-Run (Plan Without Sending Traffic)

**Always do this first!** See what requests will be made:

```bash
py -m amac probe \
  --endpoints out/endpoints.json \
  --scope scope.yml \
  --auth auth.yml \
  --dry-run
```

Review the output to ensure:
- The number of requests is reasonable
- All endpoints are in scope
- No unexpected hosts or paths

### Step 6: Run the Probe

Probe endpoints with no-auth and authenticated requests:

```bash
py -m amac probe \
  --endpoints out/endpoints.json \
  --scope scope.yml \
  --auth auth.yml \
  --identities all
```

**Options:**
- `--identities first` - Test with only the first identity (faster)
- `--identities all` - Test with all identities (RBAC matrix)
- `--out-dir out/my_run` - Custom output directory
- `--no-preview` - Skip the preview table

**Output:**
- Creates a directory like `out/run_2024-01-15_14-30-45/`
- Contains `summary.json` and `requests/*.json` files

### Step 7: Analyze Results

Generate findings from the probe run:

```bash
py -m amac analyze \
  --run-dir out/run_2024-01-15_14-30-45
```

**Output:**
- `findings.json` - Machine-readable findings
- `findings.md` - Human-readable findings

### Step 8: Generate HTML Report

Create a visual report:

```bash
py -m amac report \
  --run-dir out/run_2024-01-15_14-30-45
```

**Output:**
- `report.html` - Open in your browser for a visual report

### Complete Workflow Example

```bash
# 1. Map endpoints
py -m amac map --openapi openapi.json --scope scope.yml --out endpoints.json

# 2. Dry-run
py -m amac probe --endpoints endpoints.json --scope scope.yml --auth auth.yml --dry-run

# 3. Real probe
py -m amac probe --endpoints endpoints.json --scope scope.yml --auth auth.yml --identities all

# 4. Analyze (use the run directory from step 3)
py -m amac analyze --run-dir out/run_2024-01-15_14-30-45

# 5. Report
py -m amac report --run-dir out/run_2024-01-15_14-30-45
```

---

## Configs

### `scope.yml` (advanced example)

Disable `safe_methods_only` and list `non_safe_methods` to probe operations like
`POST` or `PUT`.

```yaml
allowed:
  - api.example.com
  - "*.dev.example.com"
denied:
  - "admin.example.com"
base_urls:
  - "https://api.example.com"

path_policy:
  deny_paths:
    - "/admin/*"
    - "re:^/internal/.*"
  allow_paths:
    - "/v1/*"
    - "/status"

request_policy:
  safe_methods_only: true
  non_safe_methods: []  # e.g., [POST, PUT]
  max_rps: 2
  concurrency: 6
  per_host_concurrency: 2
  global_jitter_ms: 80
  backoff_cap_s: 3.5
  allow_redirects: false
  verify_tls: true
  hard_request_budget: 200

timeouts:
  connect: 5
  read: 15

evidence:
  privacy_level: minimal
```

### `auth.yml` (examples)

* **Bearer demo** (for local mock): `examples/auth_demo.yml`
* **OAuth2** (client creds/password): `examples/auth_oauth2.yml`
* **Form-login cookie capture**: `examples/auth_form_login.yml`

Use multiple identities to build an **RBAC matrix**:

```bash
amac probe --identities all ...
```

---

## Commands Reference

### `amac map` - Map Endpoints from OpenAPI

Extracts endpoints from an OpenAPI/Swagger specification.

```bash
py -m amac map --openapi <file|URL> --scope <scope.yml> --out <endpoints.json>
```

**Options:**
- `--openapi` - Path to OpenAPI JSON/YAML file or URL (required)
- `--scope` - Path to scope.yml (required)
- `--out` - Output file path (default: `endpoints.json`)
- `--no-preview` - Don't show endpoint preview table

**Example:**
```bash
py -m amac map --openapi https://api.example.com/openapi.json --scope scope.yml --out endpoints.json
```

### `amac check` - Validate Configuration

Validates your scope, auth, and endpoints files before running probes.

```bash
py -m amac check --endpoints <endpoints.json> --scope <scope.yml> --auth <auth.yml>
```

**Options:**
- `--endpoints` - Path to endpoints.json (required)
- `--scope` - Path to scope.yml (required)
- `--auth` - Path to auth.yml (required)
- `--no-preview` - Don't show endpoint preview

### `amac probe` - Probe Endpoints

Sends requests to endpoints with and without authentication.

```bash
py -m amac probe --endpoints <endpoints.json> --scope <scope.yml> --auth <auth.yml>
```

**Options:**
- `--endpoints` - Path to endpoints.json (required)
- `--scope` - Path to scope.yml (required)
- `--auth` - Path to auth.yml (required)
- `--identities` - `first` or `all` (default: `all`)
- `--out-dir` - Output directory (default: auto-generated timestamped dir)
- `--dry-run` - Plan requests without sending traffic
- `--no-preview` - Don't show preview table

**Example:**
```bash
py -m amac probe --endpoints endpoints.json --scope scope.yml --auth auth.yml --identities all
```

### `amac analyze` - Analyze Probe Results

Generates security findings from a probe run.

```bash
py -m amac analyze --run-dir <run_directory>
```

**Options:**
- `--run-dir` - Directory from `amac probe` (required)
- `--no-preview` - Don't show findings preview

**Output:**
- `findings.json` - Machine-readable findings
- `findings.md` - Human-readable findings

### `amac report` - Generate HTML Report

Creates a visual HTML report from probe results.

```bash
py -m amac report --run-dir <run_directory>
```

**Options:**
- `--run-dir` - Directory from `amac probe` (required)
- `--out-html` - Custom output path (default: `{run_dir}/report.html`)

**Output:**
- `report.html` - Standalone HTML report (open in browser)

---

## Testing & Dev

```bash
py -m pip install -r requirements-dev.txt
pytest -q
ruff check .
black --check .
```

---

## Screenshots

![Dry Run](dry_run.png)
![Endpoint Mapping](map_endpoints.png)
![Real Probe](real_probe.png)

## Safety & Legal

* Use only on **authorized** targets.
* Respect program scope, SLAs, ToS, and local laws.
* Redaction is best-effort; verify outputs before sharing.

---

## License

[MIT](./LICENSE)

---

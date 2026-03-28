# Security Risk Assessment

Automated security risk assessment script for the Stellar Raise CI/CD pipeline.

## Overview

`security_risk_assessment.sh` runs six targeted checks against the repository and
produces a structured JSON report plus a human-readable summary. It is designed to
run as a CI/CD step on every push and pull request.

## Usage

```bash
# Run locally
bash scripts/security_risk_assessment.sh

# Override report output path
REPORT_JSON=reports/security.json bash scripts/security_risk_assessment.sh
```

## Checks

| # | Check | Severity on failure | Description |
|---|-------|-------------------|-------------|
| 1 | `secret_exposure` | HIGH | Scans all text files for Stellar secret key patterns (`S` + 55 base32 chars) |
| 2 | `soroban_gitignore` | HIGH | Verifies `.soroban/` is listed in `.gitignore` when it exists |
| 3 | `cargo_audit` | HIGH | Runs `cargo audit` to detect known CVEs in Rust dependencies |
| 4 | `npm_audit` | MEDIUM | Runs `npm audit --audit-level=moderate` for frontend dependencies |
| 5 | `wasm_size` | HIGH | Fails if the optimised WASM binary exceeds 256 KB |
| 6 | `clippy` | MEDIUM | Runs `cargo clippy -- -D warnings` to catch compiler warnings |

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All checks passed — risk level **LOW** |
| `1` | One or more **HIGH** severity findings |
| `2` | One or more **MEDIUM** findings, no HIGH |

## Output

### JSON Report (`security_risk_report.json`)

```json
{
  "schema_version": "1.0",
  "started_at": "2026-03-28T00:00:00Z",
  "finished_at": "2026-03-28T00:01:05Z",
  "risk_level": "LOW",
  "high_count": 0,
  "medium_count": 0,
  "findings": []
}
```

Each finding in the array has the shape:
```json
{ "severity": "HIGH", "check": "secret_exposure", "detail": "Potential Stellar secret key in .env" }
```

## CI/CD Integration

Add to `.github/workflows/rust_ci.yml`:

```yaml
- name: Security risk assessment
  run: bash scripts/security_risk_assessment.sh
  env:
    REPORT_JSON: security_risk_report.json

- name: Upload security report
  if: always()
  uses: actions/upload-artifact@v4
  with:
    name: security-risk-report
    path: security_risk_report.json
```

## Security Notes

- **Secret scanning** uses file-path output only — matched key values are never
  printed to stdout or logs (`grep -l` flag).
- The script never uses `eval` or dynamic code execution.
- All external tools (`cargo`, `npm`, `git`) are invoked by name with existence
  checks; missing tools produce MEDIUM findings rather than hard failures.
- The script can be sourced (`SOURCING=1`) for unit testing without executing `main`.

## Running Tests

```bash
bash scripts/security_risk_assessment.test.sh
```

Expected output: all tests pass, exit 0.

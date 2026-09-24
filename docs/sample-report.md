<!-- Example riskrank report (R029). Rendered from tests/fixtures/sample_report_context.py;
     a test keeps this file in sync with the template. -->

# riskrank report: http://localhost:3000

**Scanned:** 2026-09-24 10:15 UTC · **Findings:** 57 raw, 5 distinct issues · **riskrank** v1.0.0

## Summary

| Priority | Issues | Endpoints |
|---|---:|---:|
| Critical | 1 | 2 |
| High | 1 | 17 |
| Medium | 1 | 12 |
| Low | 1 | 3 |
| Not triaged | 1 | 23 |

**Fix first:** SQL Injection (Critical, score 81/100).

## Fix first (Critical and High)

### 1. [Critical] SQL Injection

- **Score:** 81/100 (exploitability 9/10 × business impact 9/10)
- **Scanner severity:** High · [CWE-89](https://cwe.mitre.org/data/definitions/89.html)
- **Found on 2 endpoints:**
  - `/rest/user/login`
  - `/rest/products/search`

**Why it matters:** The public login endpoint builds its SQL query from user input, so an attacker can log in as any user (including the admin) or read the whole user table.

**How to fix:** Use parameterised queries (Sequelize replacements) for every database call and never concatenate request data into SQL.

<details>
<summary>Evidence from the scanner</summary>

```text
' OR 1=1--
```

</details>

### 2. [High] Sensitive File Exposure

- **Score:** 48/100 (exploitability 8/10 × business impact 6/10)
- **Scanner severity:** Medium · [CWE-538](https://cwe.mitre.org/data/definitions/538.html)
- **Found on 17 endpoints:**
  - `/ftp`
  - `/ftp/incident-support.kdbx`
  - `/ftp/package.json.bak`
  - `/ftp/coupons_2013.md.bak`
  - `/ftp/acquisitions.md`
  - …and 12 more

**Why it matters:** The /ftp share is browsable without logging in and serves backups and internal documents, including a password-manager database.

**How to fix:** Remove the directory listing, move confidential files out of the web root and require authentication for anything that stays.

<details>
<summary>Evidence from the scanner</summary>

```text
incident-support.kdbx
```

</details>

## Other issues (Medium and Low)

### 3. [Medium] Content Security Policy (CSP) Header Not Set

- **Score:** 20/100 (exploitability 4/10 × business impact 5/10)
- **Scanner severity:** Medium · [CWE-693](https://cwe.mitre.org/data/definitions/693.html)
- **Found on 12 endpoints:**
  - `/`
  - `/main.js`
  - `/styles.css`
  - `/polyfills.js`
  - `/runtime.js`
  - …and 7 more

**Why it matters:** Without a CSP, any injected script runs with full access to the page, which makes cross-site scripting bugs much more damaging.

**How to fix:** Send a Content-Security-Policy header, starting with \`default-src 'self'\`.

### 4. [Low] Timestamp Disclosure - Unix

- **Score:** 2/100 (exploitability 2/10 × business impact 1/10)
- **Scanner severity:** Low · [CWE-497](https://cwe.mitre.org/data/definitions/497.html)
- **Found on 3 endpoints:**
  - `/main.js`
  - `/vendor.js`
  - `/sitemap.xml`

**Why it matters:** Unix timestamps in static files reveal little on their own and are rarely useful to an attacker.

**How to fix:** No action needed unless the values are server build times you'd rather hide.

<details>
<summary>Evidence from the scanner</summary>

```text
1650485437
```

</details>

## Not triaged

These findings have no AI assessment yet, so they are listed by the scanner's own severity.

| Issue | Scanner severity | Endpoints |
|---|---|---:|
| User Agent Fuzzer | Informational | 23 |

## How to read this report

- Findings of the same type are grouped into one issue, listing every endpoint it was found on. An issue's score and advice come from its highest-scoring occurrence.
- **Score** = exploitability × business impact (1–100), judged by an AI model in the context of each endpoint. **Critical** ≥ 64, **High** ≥ 36, **Medium** ≥ 16, **Low** below that.
- Explanations and fixes are AI-generated. Review them before acting, and only test systems you own or are authorised to test.

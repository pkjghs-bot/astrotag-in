# ASTROTAG PRE-PRODUCTION APPLICATION SECURITY AUDIT REPORT

**Role:** Principal Application Security Engineer & DevSecOps Auditor  
**Date:** November 15, 2026  
**Target:** Astrotag Precision Vedic Astrology & Agentic AI Platform  
**Deployment Target:** Vercel Serverless (Python 3.12 / Linux) + Static Edge CDN  
**Audit Standard:** OWASP Top 10 (2025), OWASP API Security Top 10 (2023), OWASP ASVS 5.0, OWASP LLM Top 10 (2025)  
**Audit Mode:** Phase 1 & 2 Read-Only Inspection & Threat Analysis  

---

## 1. Executive Summary

A comprehensive application security audit of the **Astrotag** repository was conducted prior to commercial production release. 

Astrotag's architecture consists of:
- **FastAPI backend** running on Vercel Serverless Functions (`main.py` / `index.py`)
- **Single-page static frontend** (`public/index.html` & `index.html`) using vanilla JavaScript, SVG rendering, and modern browser APIs
- **Astronomical Engine**: Swiss Ephemeris (`pysweph`) utilizing analytical Moshier calculations (`FLG_MOSEPH`)
- **External Integrations**: Open-Meteo Geocoding API, countriesnow.space, Google Gemini 2.5 Flash API (`google-genai`)

### High-Level Posture
The application is well-structured and free from hardcoded secrets or database vulnerabilities (as no persistent SQL/NoSQL database is utilized; session context is client-side). However, critical vulnerabilities exist in **API abuse and resource exhaustion (LLM cost exploitation)**, **DOM-based Cross-Site Scripting (XSS)**, **overly permissive CORS**, **missing HTTP security headers**, and **unbounded input parameters**.

| Severity | Count | Status |
| :--- | :---: | :--- |
| **CRITICAL** | 0 | None Identified |
| **HIGH** | 1 | Open (Awaiting Remediation Approval) |
| **MEDIUM** | 4 | Open (Awaiting Remediation Approval) |
| **LOW** | 3 | Open (Awaiting Remediation Approval) |
| **INFORMATIONAL**| 2 | Open (Awaiting Remediation Approval) |

---

## 2. Architecture & Threat Model

```mermaid
flowchart TD
    User["End User Browser"] -->|HTTPS / Static Assets| CDN["Vercel Edge Network / CDN"]
    User -->|API Calls (CORS * Currently)| API["FastAPI Serverless Function (Vercel)"]
    
    subgraph External_Services ["External Dependencies"]
        API -->|Geocoding Queries (Unbounded)| OpenMeteo["Open-Meteo API"]
        API -->|AI Queries (Unrestricted)| Gemini["Google Gemini 2.5 API"]
        User -->|State Dropdowns| CountriesNow["countriesnow.space API"]
    end
    
    subgraph Vulnerabilities ["Key Threat Vectors"]
        T1["Prompt Injection & Cost Drain (/api/ask-astrologer)"]
        T2["DOM XSS (Profile Banner & Popups)"]
        T3["Missing Security Headers & CSP"]
        T4["Overly Permissive CORS (allow_origins=['*'])"]
        T5["Unbounded Input Fields & DoS"]
    end
    
    API -.-> T1
    User -.-> T2
    API -.-> T3
    API -.-> T4
    API -.-> T5
```

---

## 3. Secret & Credential Leakage Audit Findings

| Audit Check | Method | Result | Notes |
| :--- | :--- | :---: | :--- |
| Git Commit History | `git log --all --full-history` | **PASS** | No credentials, keys, or tokens were ever committed. |
| Working Directory `.env` | File inspection | **PASS** | `GEMINI_API_KEY=` is an empty placeholder. |
| Source Code Pattern Scan | Regex (`secret\|password\|api_key\|token`) | **PASS** | No hardcoded API keys; `os.environ.get("GEMINI_API_KEY")` is used. |
| Client-side Bundles | Frontend HTML/JS inspection | **PASS** | No Gemini API keys or server secrets exist in `index.html`. |
| `.gitignore` Coverage | File inspection | **PARTIAL** | Ignores `.env` and `__pycache__`, but misses `.env.*` variants and IDE files. |
| `.env.example` Template | Repository scan | **FAIL** | Missing `.env.example` template for deployment teams. |

---

## 4. Vulnerability Catalog & Risk Assessment

### SEC-01: Unrestricted, Un-rate-limited AI Endpoint Leading to Prompt Injection & Denial-of-Wallet (HIGH)
- **CWE / OWASP:** OWASP LLM01:2025 (Prompt Injection), OWASP API4:2023 (Unrestricted Resource Consumption)
- **Affected File:** `main.py` (lines 1045–1085: `ask_agentic_astrologer`)
- **Vulnerability Description:**
  1. The endpoint `/api/ask-astrologer` is unauthenticated and completely lacks rate limiting or request throttling. Any automated bot or actor can submit requests in an infinite loop.
  2. The raw user input `req.question` is passed directly into `ai_client.models.generate_content(contents=req.question)` with no length validation, semantic boundaries, or sanitization.
  3. `context_data` is accepted wholesale from the untrusted client request body without schema validation, allowing arbitrary payload injection.
- **Business Impact:** Rapid quota depletion, severe API billing spikes (Denial-of-Wallet), and potential prompt injection leading to nonsensical or brand-damaging outputs.
- **Recommended Remediation:**
  - Implement in-memory IP/session rate-limiting (e.g., max 5 AI questions per minute per client IP).
  - Enforce strict character limits on `question` (e.g., min 3, max 500 characters).
  - Validate and sanitize `context_data` against a typed Pydantic schema rather than accepting raw `dict`.
  - Add prompt framing guards to reinforce system instructions against jailbreaking.

---

### SEC-02: Stored/Reflected DOM Cross-Site Scripting (XSS) via Unsanitized User Profile Inputs (MEDIUM)
- **CWE / OWASP:** CWE-79 / OWASP A03:2021 (Injection - Cross-Site Scripting)
- **Affected File:** `public/index.html` & `index.html` (lines 1168–1174, 1024–1050)
- **Vulnerability Description:**
  In `public/index.html`:
  ```javascript
  document.getElementById("profileBanner").innerHTML = `
    <div class="profile-item"><strong>Native & Birth</strong>${data.profile.name} ...
  `;
  ```
  `data.profile.name` is directly derived from user input `document.getElementById("name").value`. If an attacker enters payload `<img src=x onerror=alert(1)>` or a malicious script, it is echoed back by `/api/kundali` and rendered directly as raw HTML.
  Additionally, in `openHouseWindow()`, dynamic HTML strings are interpolated into `popup.document.write(...)` without HTML entity encoding.
- **Business Impact:** Malicious JavaScript execution in the user's browser, session hijacking, or defacement.
- **Recommended Remediation:**
  - Implement a client-side HTML escape utility (`escapeHtml(str)`) for all dynamic interpolated strings.
  - Sanitize input fields on the backend (`name` stripped of HTML tags/control characters).
  - Replace `popup.document.write` with safer DOM creation methods or explicitly encoded HTML entities.

---

### SEC-03: Missing HTTP Security Headers & Content Security Policy (MEDIUM)
- **CWE / OWASP:** CWE-1021, CWE-693 / OWASP A05:2021 (Security Misconfiguration)
- **Affected File:** `main.py` & Vercel deployment configuration
- **Vulnerability Description:**
  The server responses lack essential modern defensive HTTP headers:
  - `Content-Security-Policy` (CSP)
  - `Strict-Transport-Security` (HSTS)
  - `X-Content-Type-Options: nosniff`
  - `X-Frame-Options: DENY` (Clickjacking vulnerability)
  - `Referrer-Policy: strict-origin-when-cross-origin`
  - `Permissions-Policy`
  There is currently no `vercel.json` file specifying edge-level security headers.
- **Business Impact:** Susceptibility to clickjacking, MIME-type sniffing attacks, and cross-site data leakage.
- **Recommended Remediation:**
  - Create a production `vercel.json` configuring strict HTTP security headers at the edge CDN level.
  - Add a security headers middleware in `main.py` so local and non-Vercel deployments are equally protected.
  - Deploy a compatible Content Security Policy permitting `'self'`, `'unsafe-inline'` (for styles/SVG elements), and whitelist necessary API connections (`https://geocoding-api.open-meteo.com` and `https://countriesnow.space`).

---

### SEC-04: Overly Permissive CORS Configuration (MEDIUM)
- **CWE / OWASP:** CWE-942 / OWASP A05:2021 (Security Misconfiguration)
- **Affected File:** `main.py` (lines 72–77)
- **Vulnerability Description:**
  ```python
  app.add_middleware(
      CORSMiddleware,
      allow_origins=["*"],
      allow_methods=["*"],
      allow_headers=["*"],
  )
  ```
  Allowing all origins (`*`) with all HTTP methods (`*`) and all headers permits any third-party malicious website to execute cross-origin requests to internal calculation and AI endpoints using a visitor's network connection.
- **Business Impact:** Cross-origin API abuse, bandwidth theft, and unauthorized invocation of serverless functions.
- **Recommended Remediation:**
  - Configure CORS origins dynamically via environment variable `ALLOWED_ORIGINS` (defaulting to production domain + localhost for development).
  - Restrict allowed methods to `GET`, `POST`, `OPTIONS`.

---

### SEC-05: Missing Parameter Constraints & Potential ReDoS / Geocoder Abuse (MEDIUM)
- **CWE / OWASP:** CWE-20 / OWASP A04:2021 (Insecure Design)
- **Affected File:** `main.py` (lines 234–249, 259–302)
- **Vulnerability Description:**
  1. `BirthInput` allows arbitrarily large strings for `name`, `city`, `state`, `country`, and `pincode`.
  2. `resolve_global_location()` performs up to 4 sequential external HTTP calls with 8-second timeouts (up to 32 seconds total), which exceeds Vercel serverless default execution limits (10s–15s).
  3. No in-memory caching exists for resolved geographical coordinates, resulting in repeated external lookups for common cities (e.g., "Patna", "New Delhi", "London").
- **Business Impact:** High latency, 504 Gateway Timeouts on Vercel, and potential IP throttling from Open-Meteo.
- **Recommended Remediation:**
  - Add `Field(..., max_length=100)` constraints and regex validation for dates (`YYYY-MM-DD`) and times (`HH:MM`).
  - Introduce an LRU cache (`@functools.lru_cache` or custom TTL cache) for `resolve_global_location` to eliminate redundant geocoding latency.
  - Reduce individual HTTP timeout to 3.5s per query with an early exit on first clean match.

---

### SEC-06: Internal Error & Exception Detail Exposure (LOW)
- **CWE / OWASP:** CWE-209 / OWASP A05:2021 (Information Exposure Through an Error Message)
- **Affected File:** `main.py` (lines 988–991)
- **Vulnerability Description:**
  ```python
  except Exception as e:
      raise HTTPException(status_code=500, detail=f"{type(e).__name__}: {str(e)}")
  ```
  Returning unhandled exception class names and raw internal error strings discloses backend architecture details and stack clues to untrusted clients.
- **Business Impact:** Information disclosure aiding reconnaissance by attackers.
- **Recommended Remediation:**
  - Log internal exceptions server-side.
  - Return a sanitized, user-friendly generic message (e.g. `"Calculation error occurred. Please verify your birth details and try again."`) in HTTP 500 responses.

---

### SEC-07: Unpinned Dependencies in `requirements.txt` (LOW)
- **CWE / OWASP:** CWE-1104 / OWASP A06:2021 (Vulnerable and Outdated Components)
- **Affected File:** `requirements.txt`
- **Vulnerability Description:**
  Dependencies are completely unpinned (`fastapi`, `uvicorn`, `pysweph`, `pytz`, `google-genai`, `pydantic`). In serverless deployment builds, an upstream package release with breaking changes or supply-chain compromise could break production unexpectedly.
- **Business Impact:** Build instability, regression risks, and supply-chain vulnerabilities.
- **Recommended Remediation:**
  - Pin dependencies to tested, stable semver ranges (e.g. `fastapi>=0.115.0,<1.0.0`, `google-genai>=3.0.0,<4.0.0`, `pydantic>=2.9.0,<3.0.0`).

---

### SEC-08: Incomplete `.gitignore` and Missing `.env.example` (LOW)
- **CWE / OWASP:** CWE-552
- **Affected File:** `.gitignore`
- **Vulnerability Description:**
  The current `.gitignore` only ignores `.env`, but not `.env.local`, `.env.development`, `.env.production`, or IDE/OS metadata files. No `.env.example` exists.
- **Recommended Remediation:**
  - Expand `.gitignore` to match standard production security practices.
  - Create a sanitized `.env.example`.

---

### SEC-09: Request Body Size Limits & DoS Safeguards (LOW)
- **CWE / OWASP:** CWE-400 / OWASP A04:2021
- **Vulnerability Description:**
  FastAPI has no default request body size ceiling configured on endpoints. An attacker could send multi-megabyte JSON payloads to `/api/kundali` or `/api/ask-astrologer`.
- **Recommended Remediation:**
  - Add lightweight middleware to reject request bodies exceeding 256 KB with HTTP 413 (Payload Too Large).

---

### SEC-10: Redundant Dual File Maintenance (INFORMATIONAL)
- **Affected Files:** `index.html` and `public/index.html`
- **Description:**
  Both root `index.html` and `public/index.html` exist. Changes in one must be manually mirrored to the other, introducing drift risks.

---

## 5. Proposed Remediation Plan (Phased Roadmap)

### Stage 1: Core Backend Hardening (`main.py`)
1. **Input Validation**: Add `Field` constraints, string length limits, date/time format validation to all Pydantic models.
2. **Rate Limiting**: Implement a lightweight in-memory rate limiter for `/api/ask-astrologer` and `/api/kundali`.
3. **Payload Size Guard**: Restrict request payload size to 256 KB.
4. **CORS Hardening**: Configure environment-driven CORS origins.
5. **Geocoding Resilience & Cache**: Add LRU caching and timeout safeguards to `resolve_global_location`.
6. **Error Sanitization**: Replace raw exception leakage with sanitized responses.

### Stage 2: Frontend Hardening (`public/index.html` & `index.html`)
1. **XSS Defense**: Implement an `escapeHtml()` utility for all user-derived values (`name`, `city`, etc.) before DOM insertion.
2. **Safe DOM Popups**: Sanitize dynamic strings written to child windows.

### Stage 3: Infrastructure, Edge Configuration & DevSecOps
1. **Vercel Edge Security**: Create `vercel.json` with HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, and cache headers.
2. **Secret Management**: Update `.gitignore` and create `.env.example`.
3. **Dependency Pinning**: Update `requirements.txt` with safe semver ranges.

### Stage 4: Testing & Verification
1. Execute unit and API integration tests covering XSS payloads, invalid inputs, rate limits, and error handling.
2. Verify frontend rendering, North Indian chart SVGs, transits, and Ayanamsa calculations remain 100% functional.

### Stage 5: Security Documentation
Generate all required compliance documents:
- `SECURITY_AUDIT_REPORT.md`
- `SECURITY_REMEDIATION_REPORT.md`
- `SECURITY_CHECKLIST.md`
- `SECRET_MANAGEMENT_GUIDE.md`
- `VERCEL_PRODUCTION_SECURITY.md`
- `INCIDENT_RESPONSE_PLAN.md`

---

## 6. Release Gate Status (Pre-Remediation)

| Domain | Status | Reason |
| :--- | :---: | :--- |
| Secret Leakage | **PASS** | No secrets committed or exposed. |
| Authentication & Access Control | **N/A** | App is currently public stateless utility. |
| API & Backend Security | **FAIL** | Unrestricted AI endpoint, lack of rate limits, unbounded inputs. |
| Frontend Security | **FAIL** | Unescaped user input in `innerHTML` (DOM XSS vector). |
| Transport & Headers | **FAIL** | Missing CSP, HSTS, X-Frame-Options, edge security headers. |
| Supply Chain & Packaging | **PARTIAL** | Dependencies unpinned; missing lockfile / pinned ranges. |
| **Overall Pre-Launch Status** | **FAIL** | Remediations required prior to commercial release sign-off. |

# ASTROTAG VERCEL PRODUCTION SECURITY & INFRASTRUCTURE GUIDE

**Document Version:** 1.0.0  
**Effective Date:** November 15, 2026  
**Audience:** Cloud Architects, DevOps Engineers, Operations  

---

## 1. Architectural Overview

Astrotag is deployed as a hybrid serverless web application on **Vercel**:
- **Static Edge Tier**: `public/index.html` (and root `index.html`) served from Vercel's global Anycast Edge Network with high-performance asset compression (Brotli/Gzip).
- **Compute Tier**: FastAPI application running as an ASGI serverless function on Python 3.12 (AWS Lambda / Vercel Serverless runtime).
- **Ephemeris Engine**: Built-in analytical Moshier ephemeris (`FLG_MOSEPH`), which requires zero external `.se1` ephemeris files on the serverless disk.
- **Client-Side Session State**: All chart state is held in the browser and transmitted in stateless follow-up payloads, ensuring 100% serverless compatibility across cold starts.

---

## 2. Edge Security Configuration (`vercel.json`)

Vercel applies security headers directly at the edge CDN before requests reach serverless functions:

```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        {
          "key": "X-Content-Type-Options",
          "value": "nosniff"
        },
        {
          "key": "X-Frame-Options",
          "value": "DENY"
        },
        {
          "key": "Referrer-Policy",
          "value": "strict-origin-when-cross-origin"
        },
        {
          "key": "Permissions-Policy",
          "value": "camera=(), microphone=(), geolocation=(), payment=()"
        },
        {
          "key": "Strict-Transport-Security",
          "value": "max-age=63072000; includeSubDomains; preload"
        },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://geocoding-api.open-meteo.com https://countriesnow.space; frame-ancestors 'none'; base-uri 'self'; form-action 'self';"
        }
      ]
    }
  ]
}
```

### Content Security Policy (CSP) Breakdown
- `default-src 'self'`: Default restricts all external asset loading.
- `script-src 'self' 'unsafe-inline'`: Allows embedded scripts in `index.html` while disallowing loading arbitrary third-party `.js` scripts.
- `style-src 'self' 'unsafe-inline'`: Permits embedded CSS styling and fonts.
- `img-src 'self' data:`: Permits inline SVG generation and embedded image rendering.
- `connect-src 'self' https://geocoding-api.open-meteo.com https://countriesnow.space`: Restricts browser `fetch()` requests strictly to self and the two trusted geocoding/region APIs.
- `frame-ancestors 'none'`: Prevents clickjacking by forbidding any domain from embedding Astrotag in an iframe.

---

## 3. Serverless Execution & Timeout Optimization

Vercel Serverless Functions have execution duration limits (10s on Hobby, up to 60s on Pro/Enterprise). To avoid HTTP 504 Gateway Timeouts:

1. **Short Circuit Geocoding**:
   The geocoder performs lookups with a strict **3.5s socket timeout** and returns on the first clean match.
2. **In-Memory LRU Cache**:
   The `GEO_CACHE` dictionary caches up to 1024 unique geographic locations per function container, eliminating redundant HTTP roundtrips.
3. **No Heavy External Dependencies**:
   By omitting `pandas`, `geopy`, `timezonefinder`, and binary ephemeris tables, cold start times remain under **250ms**, and memory footprint is well below the 250 MB ceiling.

---

## 4. Edge DDoS & Rate Limiting

1. **Vercel Web Analytics & Firewall**:
   - Enable Vercel **Attack Challenge Mode** under Project Settings if anomalous traffic surges occur.
   - Set up IP blocklists or rate-limiting rules if specific autonomous scrapers target the domain.
2. **Application-Level Defense**:
   - `limiter_kundali` enforces 30 calculations per minute per client IP.
   - `limiter_ai` enforces 6 questions per minute per client IP.
   - `limiter_transit` enforces 30 transit snapshots per minute per client IP.
   - Exceeded limits trigger immediate `HTTP 429 Too Many Requests` responses with `Retry-After: 60` headers without invoking external APIs.

---

## 5. Domain & SSL/TLS Setup

1. **Add Custom Domain**:
   - In the Vercel Dashboard, go to **Settings** &rarr; **Domains**.
   - Add your apex domain (e.g., `astrotag.com`) and `www.astrotag.com`.
2. **DNS Configuration**:
   - Point Apex A Record: `76.76.21.21`
   - Point CNAME for `www`: `cname.vercel-dns.com`
3. **Automatic TLS Certificate**:
   - Vercel automatically provisions and renews 2048-bit RSA / ECC SSL certificates from Let's Encrypt.
   - HTTPS redirect is enforced automatically.
4. **HSTS Preloading**:
   - The edge response includes `Strict-Transport-Security: max-age=63072000; includeSubDomains; preload`, allowing submission to [hstspreload.org](https://hstspreload.org).

---

## 6. Runtime Logging & Monitoring

1. **Vercel Runtime Logs**:
   - Inspect live serverless logs under the **Logs** tab in the Vercel Dashboard.
   - The hardened backend logs rate-limit violations at `WARNING` level:
     ```
     2026-11-15 12:00:00 [WARNING] astrotag: AI Astrologer rate limit exceeded for IP 198.51.100.42
     ```
   - Unhandled exceptions are logged with full stack traces at `ERROR` level, while the user receives a safe generic error response.
2. **Log Drains**:
   - For enterprise auditing, connect a Vercel Log Drain to Datadog, Axiom, or Better Stack.

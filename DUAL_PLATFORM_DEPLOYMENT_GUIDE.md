# ASTROTAG DUAL-PLATFORM DEPLOYMENT GUIDE (VERCEL + CLOUDFLARE PAGES + RENDER + ADSENSE)

**Document Version:** 2.0.0  
**Effective Date:** November 15, 2026  
**Audience:** DevOps Engineers, Cloud Administrators, Developers  

---

## 1. Architectural Overview

Astrotag is engineered to run simultaneously on **Vercel** and **Cloudflare Pages** (supporting both `astro.in` and `astrotag.in` via GoDaddy DNS) with full **Google AdSense** integration while maintaining complete OWASP ASVS compliance (strict CORS, CSP, HSTS, rate limiting, and zero secret leakage):

```mermaid
flowchart TD
    User["Visitor Browser (astro.in / astrotag.in / *.vercel.app / *.pages.dev)"]
    
    subgraph Track_A ["Stack 1: Vercel Native"]
        V_Edge["Vercel Edge Network (vercel.json)"]
        V_Func["Vercel Serverless Function (FastAPI main.py)"]
        V_Edge -->|Static Files / HTML + CSP| User
        User -->|host.endsWith('vercel.app') -> API_BASE = ''| V_Func
    end
    
    subgraph Track_B ["Stack 2: Cloudflare Pages + Render"]
        CF_Edge["Cloudflare Pages (_headers)"]
        Render_API["Render Python Service (astrotag-api.onrender.com)"]
        CF_Edge -->|Static Files / HTML + CSP| User
        User -->|astro.in / astrotag.in / *.pages.dev -> API_BASE = Render| Render_API
    end
    
    subgraph AdSense_Network ["Monetization & Policies"]
        User -->|Ad Delivery| AdSense["Google AdSense (ca-pub-XXXXXXXXXXXXXXXX)"]
        User -->|Policy Discovery| Policies["/privacy-policy.html, /about.html, /disclaimer.html, /contact.html, /ads.txt"]
    end
```

---

## 2. Frontend Origin-Aware Dynamic Router

In `public/index.html` (and root `index.html`), the client automatically detects its hosting host:

```javascript
const RENDER_BACKEND_URL = "https://astrotag-api.onrender.com";
const host = window.location.hostname;

// On Vercel (*.vercel.app) or localhost, use same-origin /api/*.
// On Cloudflare Pages (astro.in, astrotag.in, *.pages.dev), route API calls to Render.
const API_BASE = (host.endsWith("vercel.app") || host === "localhost" || host === "127.0.0.1")
  ? ""
  : RENDER_BACKEND_URL;
```

All 4 application fetch calls automatically route through `${API_BASE}`:
1. `${API_BASE}/api/kundali`
2. `${API_BASE}/api/transit`
3. `${API_BASE}/api/dasha-sublevels`
4. `${API_BASE}/api/ask-astrologer`

---

## 3. Backend Hardened CORS Security Layer

In `main.py`, CORS explicitly permits `astro.in`, `astrotag.in`, Cloudflare Pages, and Vercel without wildcard exposure:

```python
ALLOWED_ORIGINS = [
    "https://astro.in",
    "https://www.astro.in",
    "https://astrotag.in",
    "https://www.astrotag.in",
    "https://astrotag.pages.dev",
    "https://astrotag.vercel.app",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
]

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_origin_regex=r"^https://([a-z0-9-]+\.)?(astro|astrotag)\.(in|pages\.dev|vercel\.app)$",
    allow_credentials=False,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Content-Type"],
    max_age=3600,
)
```

Preflight OPTIONS requests from `https://astro.in` or `https://astrotag.in` receive `access-control-allow-origin` matching their origin.

---

## 4. Google AdSense Integration & Policy Pages

Google AdSense requires specific static editorial content, policy disclosures, and `ads.txt` before approving a domain.

### A. AdSense Code in `<head>`
```html
<script async src="https://pagead2.googlesyndication.com/pagead/js/adsbygoogle.js?client=ca-pub-XXXXXXXXXXXXXXXX"
     crossorigin="anonymous"></script>
```
*(Replace `ca-pub-XXXXXXXXXXXXXXXX` with your verified AdSense Publisher ID).*

### B. `ads.txt`
Stored at `public/ads.txt` and served at root `/ads.txt`:
```
google.com, pub-XXXXXXXXXXXXXXXX, DIRECT, f08c47fec0942fa0
```

### C. 4 Static Compliance Pages
- **`/privacy-policy.html`**: Discloses stateless architecture, Google AdSense third-party cookies, DoubleClick DART cookies, log files, and opt-out links.
- **`/about.html`**: Details Astrotag's astronomical basis (Swiss Ephemeris / Moshier analytical model, Lahiri/Raman/KP Ayanamsas, 16 Parashari Vargas, 6-level Dasha).
- **`/disclaimer.html`**: Disclaims medical, legal, and financial liability for astrological and AI interpretations.
- **`/contact.html`**: Publisher channels (`support@astrotag.in`) and editorial turnaround commitments.

### D. Educational Knowledge Base (600–800 words)
Embedded in `index.html` below the chart workspace to avoid Google's "Thin Content / Pure Tool" rejection penalty.

---

## 5. AdSense-Compatible Security Headers & CSP

Both platforms enforce identical security headers that permit Google AdSense while protecting against XSS and clickjacking:

### A. Cloudflare Pages (`public/_headers` and `_headers`)
```
/*
  Strict-Transport-Security: max-age=63072000; includeSubDomains; preload
  X-Content-Type-Options: nosniff
  Referrer-Policy: strict-origin-when-cross-origin
  Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()
  Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://adservice.google.com https://www.googleadservices.com https://partner.googleadservices.com https://tpc.googlesyndication.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://astrotag-api.onrender.com https://countriesnow.space https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net; frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

### B. Vercel (`vercel.json`)
```json
{
  "$schema": "https://openapi.vercel.sh/vercel.json",
  "headers": [
    {
      "source": "/(.*)",
      "headers": [
        { "key": "Strict-Transport-Security", "value": "max-age=63072000; includeSubDomains; preload" },
        { "key": "X-Content-Type-Options", "value": "nosniff" },
        { "key": "X-Frame-Options", "value": "DENY" },
        { "key": "Referrer-Policy", "value": "strict-origin-when-cross-origin" },
        { "key": "Permissions-Policy", "value": "camera=(), microphone=(), geolocation=(), payment=()" },
        {
          "key": "Content-Security-Policy",
          "value": "default-src 'self'; script-src 'self' 'unsafe-inline' https://pagead2.googlesyndication.com https://adservice.google.com https://www.googleadservices.com https://partner.googleadservices.com https://tpc.googlesyndication.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; connect-src 'self' https://astrotag-api.onrender.com https://countriesnow.space https://pagead2.googlesyndication.com https://googleads.g.doubleclick.net; frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com; frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
        }
      ]
    }
  ]
}
```

---

## 6. GoDaddy DNS Configuration for `astro.in` / `astrotag.in`

### Pointing to Vercel:
| Type | Name | Value | TTL |
| :--- | :--- | :--- | :--- |
| **A** | `@` | `76.76.21.21` | 1 Hour / Automatic |
| **CNAME** | `www` | `cname.vercel-dns.com` | 1 Hour / Automatic |

### Pointing to Cloudflare Pages:
In Cloudflare Pages Dashboard &rarr; **astrotag** &rarr; **Custom Domains** &rarr; Add `astro.in` (or `astrotag.in`):
| Type | Name | Value | TTL |
| :--- | :--- | :--- | :--- |
| **CNAME** | `@` | `astrotag.pages.dev` (or Cloudflare Nameservers) | 1 Hour / Automatic |
| **CNAME** | `www` | `astrotag.pages.dev` | 1 Hour / Automatic |

---

## 7. Render Python Backend Setup (`astrotag-api.onrender.com`)

When using Cloudflare Pages for the frontend:
1. In [render.com](https://render.com), create a new **Web Service** connected to your repo `pkjghs-bot/Astrotag`.
2. Configure settings:
   - **Environment:** `Python 3`
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
3. Environment Variables:
   - `GEMINI_API_KEY`: `AIzaSy...`
   - `ALLOWED_ORIGINS`: `https://astro.in,https://www.astro.in,https://astrotag.in,https://www.astrotag.in,https://astrotag.pages.dev`
4. Deploy the service.

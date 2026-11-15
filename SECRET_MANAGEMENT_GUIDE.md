# ASTROTAG SECRET & CREDENTIAL MANAGEMENT GUIDE

**Document Version:** 1.0.0  
**Effective Date:** November 15, 2026  
**Audience:** Developers, DevOps Engineers, Cloud Administrators  

---

## 1. Overview & Philosophy

The Astrotag platform enforces a **Zero-Secret Ingestion** and **Ephemeral Injection** architecture:
1. **Never Commit Secrets to Version Control**: No API keys, tokens, or credentials may be written to code or checked into Git.
2. **Never Expose Server Secrets to the Client**: Frontend code (`public/index.html`, `index.html`) must never receive or process raw private API keys.
3. **Least Privilege & Scoped Access**: Keys must be restricted in scope and quota to prevent Denial-of-Wallet exploitation.

---

## 2. Credential Inventory

| Credential Name | Scope | Purpose | Storage Location | Sensitivity |
| :--- | :--- | :--- | :--- | :---: |
| `GEMINI_API_KEY` | Server-Side Only | Powers `/api/ask-astrologer` synthesis via Google GenAI SDK | Vercel Environment Variables (`Production`, `Preview`) / Local `.env` | **CRITICAL** |
| `ALLOWED_ORIGINS` | Configuration | Defines trusted domains permitted for Cross-Origin requests | Vercel Environment Variables / Local `.env` | **LOW** |

---

## 3. Local Development Workflow

1. **Clone Repository**:
   ```bash
   git clone https://github.com/pkjghs-bot/Astrotag.git
   cd Astrotag
   ```

2. **Initialize Local `.env`**:
   Copy the sanitized template:
   ```bash
   cp .env.example .env
   ```

3. **Populate Local Secrets**:
   Edit `.env` locally:
   ```ini
   GEMINI_API_KEY=AIzaSy...your_actual_key_here
   ALLOWED_ORIGINS=http://localhost:8000,http://127.0.0.1:8000
   ```

4. **Verify `.gitignore` Status**:
   Before staging any commit, always verify `.env` is ignored:
   ```bash
   git status --ignored
   ```
   Ensure `.env` appears under `Ignored files`, never under `Changes not staged for commit` or `Untracked files`.

---

## 4. Vercel Production Environment Configuration

### Option A: Via Vercel Web Dashboard (Recommended)
1. Navigate to [vercel.com](https://vercel.com) and select the **Astrotag** project.
2. Go to **Settings** &rarr; **Environment Variables**.
3. Add a new variable:
   - **Key:** `GEMINI_API_KEY`
   - **Value:** `AIzaSy...` (Your production Gemini API key)
   - **Environments:** Select `Production` and `Preview`.
4. Add the CORS variable:
   - **Key:** `ALLOWED_ORIGINS`
   - **Value:** `https://your-custom-domain.com,https://astrotag.vercel.app`
   - **Environments:** Select `Production` and `Preview`.
5. Click **Save** and trigger a redeployment for the changes to take effect.

### Option B: Via Vercel CLI
```bash
# Add GEMINI_API_KEY for production
vercel env add GEMINI_API_KEY production

# Add ALLOWED_ORIGINS for production
vercel env add ALLOWED_ORIGINS production
```

---

## 5. Secret Rotation Procedures

### Scheduled Rotation (Every 90 Days)
To rotate `GEMINI_API_KEY` with zero application downtime:
1. Log in to [Google AI Studio](https://aistudio.google.com/app/apikey).
2. Generate a **new API key** with identical project quotas.
3. Update the `GEMINI_API_KEY` value in the Vercel Dashboard for both `Production` and `Preview`.
4. Trigger an immediate production deployment:
   ```bash
   vercel --prod
   ```
5. Test the `/api/ask-astrologer` endpoint on production to verify successful synthesis with the new key.
6. Once verified, return to Google AI Studio and **delete the old API key**.

### Emergency Leak Rotation Protocol
If an API key is suspected to be compromised:
1. **Immediate Revocation**: Go to Google AI Studio and delete the compromised key immediately.
2. **Issue Replacement**: Generate a brand new API key.
3. **Deploy Key**: Update Vercel Environment Variables and redeploy.
4. **Audit Billing & Usage**: Review Google Cloud Billing and API Usage metrics for anomalous traffic or quota spikes.
5. **Incident Documentation**: Document the incident according to `INCIDENT_RESPONSE_PLAN.md`.

---

## 6. Git Leak Prevention & Remediation

### Pre-Commit Validation
Developers are encouraged to install `gitleaks` or `trufflehog` locally:
```bash
# Example scan before pushing
gitleaks detect --source . -v
```

### If a Secret Is Accidentally Committed
If a credential is ever committed to a local branch or pushed to GitHub:
1. **Consider the key permanently compromised**: Rotate/revoke it immediately at the provider level.
2. **Never attempt to overwrite the commit with a new commit**: The secret remains in Git history.
3. **Purge from History using `git-filter-repo`**:
   ```bash
   git filter-repo --replace-text <(echo "leaked_secret_string==>REDACTED")
   git push origin --force --all
   ```
4. Revoke the key and issue a new one.

# m365-email-security

A hands-on guide to securing a **Microsoft 365** domain against spoofing and phishing with **SPF, DKIM, and DMARC**, plus a **least-privilege Entra ID app registration** for automated mail. Built while standing up a real M365 tenant — documented so the *why* is as clear as the *how*.

> ⚠️ Everything here is sanitized. Replace `example.com`, the tenant name, and any GUIDs with your own. No secrets are committed — and none ever should be.

---

## The problem
By default, anyone on the internet can send email *claiming* to be from your domain. The three records below are how a receiving server decides whether to trust that claim — they're the front line against domain spoofing and phishing.

## The three records

### 1. SPF — *who is allowed to send for my domain?*
A DNS `TXT` record listing the mail servers authorized to send as your domain. The receiver checks the sending server's IP against it.

```
TXT  @  "v=spf1 include:spf.protection.outlook.com -all"
```
- `include:spf.protection.outlook.com` → authorize Microsoft 365's servers
- `-all` = hard fail (reject anything else) · `~all` = soft fail (flag, common while testing)
- ⚠️ Only **one** SPF record per domain.

### 2. DKIM — *a signature that proves the message wasn't forged or altered*
M365 signs each outgoing message with a private key; the public key lives in DNS via two CNAMEs. The receiver verifies the signature. DKIM also **survives forwarding**, which SPF often doesn't.

```
CNAME  selector1._domainkey  selector1-example-com._domainkey.<tenant>.onmicrosoft.com
CNAME  selector2._domainkey  selector2-example-com._domainkey.<tenant>.onmicrosoft.com
```
> Newer M365 tenants use a `…<tenant>.r-v1.dkim.mail.microsoft` target instead of `.onmicrosoft.com`. **Always read the exact CNAME values from `Get-DkimSigningConfig`** — don't assume. See [`scripts/Enable-DkimSigning.ps1`](scripts/Enable-DkimSigning.ps1).

### 3. DMARC — *the policy that ties it together + tells me what failed*
Says what a receiver should do when a message fails **both** SPF and DKIM, and where to send reports.

```
TXT  _dmarc  "v=DMARC1; p=none; rua=mailto:dmarc@example.com; fo=1"
```
- `p=none` → monitor only · `p=quarantine` → spam folder · `p=reject` → block
- **Rollout:** start at `none`, read the `rua` reports, then tighten to `quarantine` and `reject`.
- **Alignment** is the key idea: DMARC passes only if the visible `From:` domain matches the domain that passed SPF/DKIM. That's what actually stops spoofing.

## Bonus: least-privilege app for automated mail
To let a script send mail via Microsoft Graph without a signed-in user, you register an **Entra ID app** with the `Mail.Send` *application* permission. By default that lets the app send as **any** mailbox in the tenant — too much power. Scope it down to a single mailbox with an **Application Access Policy**. See [`scripts/New-ScopedGraphMailApp.ps1`](scripts/New-ScopedGraphMailApp.ps1).

## What I took away
- SPF authorizes, DKIM proves integrity, DMARC enforces + reports — you need all three.
- **Read config from the source of truth** (`Get-DkimSigningConfig`) instead of assuming record values.
- **Least privilege everywhere** — scope an app to one mailbox, not the whole tenant.
- DNS changes aren't instant — **lower the TTL before** changing a record so it propagates fast.

## Verify your setup
- MX/SPF/DKIM/DMARC lookup: [mxtoolbox.com](https://mxtoolbox.com/SuperTool.aspx)
- Microsoft geo-agnostic checks via PowerShell — see the scripts.

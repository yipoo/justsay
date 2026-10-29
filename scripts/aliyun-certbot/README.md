# JustSay Alibaba Cloud Certbot deployment

Based on [devsapp/fc-certbot](https://github.com/devsapp/fc-certbot), upstream
commit `4437a262051d2bc9593d92e2d48ea17bd597dd7f` (template 0.0.7).

Runtime region for both functions: **`cn-beijing` (华北 2 / 北京)**.
The original template project `justsay-certbot` was created in Hangzhou and is
retained only as deployment history. Its Hangzhou and Singapore timers and
on-demand functions have been disabled.

- Issuer function: `justsay-cert-generator`.
- Rotation manager: `justsay-cert-domain-manager`.
- Managed domain: `justsay.api.53kj.com` in `cn-beijing`.
- Enabled timer: every day at 00:00 Asia/Shanghai (also 00:00 Singapore).
- FC role created through the template: `fc-cap-role-73ha`.

## Compatibility fixes

The upstream template pins Certbot 2.11.1 but permits newer ACME/OpenSSL
dependencies. Its first invocation failed with `OpenSSL.crypto.X509Req` missing.
The JustSay package pins Certbot and ACME to 5.8.0, with cryptography 50.0.2.
RSA PKCS#1 conversion uses Python cryptography, independent of the host OpenSSL
command's default output format.

The issuer rejects other hostnames. The manager checks only Beijing and filters
the exact JustSay domain before making any certificate changes. It keeps the
upstream `devs-certbot-generated-` certificate naming scheme so automatic rotation
can recognize the managed certificate. Certificates become due when fewer than
seven days remain, matching the upstream template.

## Build and deploy

Use `build.sh /absolute/output/directory` to prepare Linux x86_64 Python 3.10
and Node.js ZIP packages. Upload `cert-generator.zip` to the issuer function and
`cert-domain-manager.zip` to the manager function using FC's ZIP upload UI.
The source also suppresses SDK debug logging after Certbot runs, because
upstream debug output can include certificate private keys in upload requests.
No secrets are included in these packages; FC injects temporary role credentials.

The sources in this directory are the maintained copies. Redeploying the original
unmodified template would overwrite the compatibility fixes and domain filter.

After deploying, invoke the issuer with:

```json
{"domainName":"justsay.api.53kj.com"}
```

Select the resulting `devs-certbot-generated-*` certificate in the Beijing FC
custom-domain certificate configuration. Then invoke the manager with `{}` and
confirm success before relying on its daily timer. Verify trusted HTTPS and
`https://justsay.api.53kj.com/health` after binding.

## Verified deployment (2026-10-29)

Both functions are deployed in Beijing. The issuer successfully issued certificate
`28151503`, named `devs-certbot-generated-justsay-beijing`, and the Beijing custom
domain uses it. Manual invocation of the Beijing manager returned `done` (request
`1-6ae2adbf-13e56b67-1c86f5daefd3`). The enabled Beijing trigger is `time-trigger`,
with expression `CRON_TZ=Asia/Shanghai 0 0 0 * * *` on `LATEST`.

Public TLS verification confirmed Let's Encrypt YR1 and expiry **2027-01-27
01:21:23 UTC** (09:21:23 Beijing/Singapore). `/health` returned HTTP 200 and
`{"ok":true}`. The migration checked that route, protocol, authentication, TLS
and WAF settings were preserved. The next scheduled run is separate from the
successful manual verification; no scheduled execution is claimed yet.

The unused initial test certificate was revoked after upstream SDK debug logs
exposed its key. The deployed logging fix suppresses that upload debug output.
`scripts/aliyun-certbot/cert-generator/migration.py` records the completed one-time
migration and is guarded to run only in the original Hangzhou function. Do not
run it as part of ordinary Beijing renewal or future deployments.

GitHub's alternative `certificate.yml` remains disabled to avoid a duplicate
renewal scheduler. No MemoryAI functions or certificate state are shared.

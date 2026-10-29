# JustSay certificate renewal in Beijing

> Active and verified on 2026-10-29. The execution role now has only custom
> policy `JustSayCertificateRenewalBeijing` (default version `v2`). All three
> template FullAccess policies have been detached. Cutover used signed CLI API
> calls from Alibaba Cloud Shell's existing identity; no long-lived AccessKey
> was created or exported.

Both functions run in **cn-beijing (华北 2 / 北京)**, independently of MemoryAI.
The original implementation came from [devsapp/fc-certbot](https://github.com/devsapp/fc-certbot),
commit `4437a262051d2bc9593d92e2d48ea17bd597dd7f`. The maintained version removes
the template's certificate-store dependency and deployment permissions.

## Runtime

- Issuer: `justsay-cert-generator`, Python 3.10, Certbot/ACME 5.8.0.
- Timer manager: `justsay-cert-domain-manager`, Node.js 20.
- Domain: `justsay.api.53kj.com`; application function: `justsay-api` in Beijing.
- Timer: `time-trigger`, `LATEST`, enabled daily at **00:00 Asia/Shanghai**
  (also 00:00 Singapore).
- Execution role: `fc-cap-role-73ha`.

The manager invokes only the Beijing issuer's `LATEST` version. The issuer checks
the live trusted TLS certificate over public HTTPS. With at least seven days
remaining, it returns `not_due` without cloud writes. When due, it uses DNS-01 to
issue a production certificate, updates only the exact Beijing domain's
`certConfig`, and verifies the live certificate serial number.

No certificate is uploaded to CAS. The role no longer needs certificate-store
list, download, upload, or delete permissions. Function responses contain status
and expiry metadata only, never private keys. Certbot runs in a separate process;
SDK debug output and raw exception requests are not printed. Temporary ACME files
are deleted after the invocation.

## Least-privilege policy

[`ram-policy.json`](ram-policy.json) is the active replacement for the template's
three broad policies (`AliyunDNSFullAccess`, `AliyunFCFullAccess`, and
`AliyunYundunCertFullAccess`). Its five allowed actions are:

| Actions | Resource scope |
| --- | --- |
| `fc:InvokeFunction` | `justsay-cert-generator`, Beijing only; the timer invokes `LATEST` |
| `fc:UpdateCustomDomain` | `justsay.api.53kj.com`, Beijing only |
| `alidns:DescribeDomainRecords`, `alidns:AddDomainRecord`, `alidns:DeleteDomainRecord` | DNS zone `53kj.com` only |

There are no wildcard resource grants, RAM permissions, code/deployment changes,
function/trigger creation or deletion, other-domain FC updates, or CAS access.

**DNS authorization boundary:** Alibaba Cloud DNS grants these APIs at hosted-zone
granularity, not individual TXT record granularity. The policy therefore permits
those three actions within `53kj.com`; the hook additionally restricts changes to
`_acme-challenge.justsay.api` and the exact current order value. It never updates
an existing record or deletes unrelated TXT values. This is not a claim that RAM
itself isolates one TXT record. See the official
[DNS policy reference](https://help.aliyun.com/en/dns/alibaba-cloud-dns-custom-permission-policy-reference-dns)
and [FC policy resource reference](https://help.aliyun.com/en/functioncompute/policies-and-sample-policies).

## Deploy and verify

```sh
scripts/aliyun-certbot/build.sh /absolute/output/directory
```

Upload `cert-generator.zip` and `cert-domain-manager.zip` to the corresponding
Beijing functions. The original gallery project remains as history only; its
Hangzhou and Singapore timers/functions were disabled. Do not redeploy the
unmodified gallery template, which would restore broader behavior.

Create/attach the exact custom RAM policy to the execution role and detach all
three FullAccess policies. Administrative deployment uses the signed-in console
account; the runtime role does not need to deploy its own code or manage RAM.

For CLI maintenance, prepare the two ZIP packages and a `manifest.json` mapping
package filenames to their SHA-256 digests in a private working folder alongside
`cloud-cutover.py` and `ram-policy.json`. Run in Cloud Shell, which supplies its
own temporary CLI identity:

```sh
python3 cloud-cutover.py             # read-only target, policy and health checks
python3 cloud-cutover.py --apply     # backup, restrict, deploy, issue and verify
```

The script guards the account, role, Beijing domain route and timer, verifies the
policy document and package hashes, and backs up deployed code privately before
changing anything. It restores prior permissions, code and domain settings if
verification fails. `--apply --verify-only` is for checking an invocation-policy
fix **after** a completed production renewal; it does not repeat DNS issuance or
prove those write permissions by itself. Private rollback backups remain outside
Git in the temporary Cloud Shell VM.

FC authorizes the function invocation against the function ARN without a version
suffix in this deployment. The policy grants that exact function ARN; using only
`/LATEST` caused an invocation denial. The manager still explicitly invokes
`LATEST`. The isolation probe must actually receive an access denial when trying
`fc:ListFunctions`, rather than treating arbitrary network failures as a pass.

Issuer test events:

- `{}`: ordinary daily check, no issuance unless fewer than seven days remain.
- `{"action":"verify_isolation"}`: confirm `fc:ListFunctions` is denied; metadata only.
- `{"action":"dry_run"}`: real DNS-01 issuance against Let's Encrypt **staging**;
  never installs the untrusted certificate.
- `{"action":"force_renew"}`: maintenance-only production issuance and binding.
  Use sparingly because Let's Encrypt rate limits apply.

Invoke the manager with `{}` after applying the restricted policy. A successful
`not_due` check verifies invocation and public TLS, but does **not** prove DNS or
certificate-update permissions. Verify a complete renewal under the restricted
policy and confirm trusted HTTPS and `/health` before declaring the cutover done.

Tests:

```sh
uv run --no-project --with-requirements scripts/aliyun-certbot/cert-generator/requirements.txt \
  python -m unittest discover -s scripts/aliyun-certbot/tests -v
```

A clean extracted Node package must also import `index.js` successfully; all
runtime imports are explicit dependencies.

## GitHub state

The alternative GitHub renewal workflow is disabled, with
`CERT_DNS_AUTOMATION_ENABLED=false`. Both unused Secrets,
`ACME_BOOTSTRAP_STATE` and `ACME_STATE_ENCRYPTION_KEY`, were deleted on 2026-10-29;
GitHub reported zero remaining repository Secrets. The public repository contains
source and policy documents only. No cloud access key is stored in GitHub.

## Verified deployment (2026-10-29)

- Both functions are deployed to Beijing, using the restricted role.
- RAM lists only custom policy `JustSayCertificateRenewalBeijing`; no FullAccess
  policy remains attached. The five actions and resource scopes are in the JSON.
- Real DNS-01 staging issuance and production issuance/binding succeeded with the
  restricted DNS and domain-update permissions. DNS records were cleaned up.
- After correcting the invocation ARN, a fresh restricted runtime confirmed that
  `fc:ListFunctions` is denied, and the daily manager returned `not_due` normally.
  A second production order was deliberately avoided during this invocation fix.
- The enabled timer remains daily at 00:00 Beijing/Singapore. This verifies manual
  execution of its function chain; it does not claim a scheduled run has occurred.
- Public HTTPS trusts Let's Encrypt **YR2**, serial
  `06D08AA856D767134B8263A75F43657CE9B9`, expiring **2027-01-27 02:05:24 UTC**
  (**10:05:24 Beijing/Singapore**). `/health` returned HTTP 200 and `{"ok":true}`.
- Route, protocol, authentication, TLS and WAF settings were checked and preserved.
- Seven local regression tests and GitHub CI passed. GitHub retains zero repository
  Secrets, and the alternative renewal workflow remains manually disabled.

# JustSay certificate renewal in Beijing

> RAM cutover is blocked by Alibaba Cloud console security verification. The
> cloud functions were restored to the previously verified baseline from commit
> `48d6d11`. The reduced-permission source below is a tested candidate for the
> next deployment, not the currently active runtime.

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

[`ram-policy.json`](ram-policy.json) is the intended replacement for the template's
three broad policies (`AliyunDNSFullAccess`, `AliyunFCFullAccess`, and
`AliyunYundunCertFullAccess`). Its five allowed actions are:

| Actions | Resource scope |
| --- | --- |
| `fc:InvokeFunction` | `justsay-cert-generator/LATEST`, Beijing only |
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

Issuer test events:

- `{}`: ordinary daily check, no issuance unless fewer than seven days remain.
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

## Verification status

The reduced-permission candidate passed local tests and GitHub CI. RAM cutover
and post-cutover issuance verification are pending console security verification.
The original verified Beijing implementation remains the production baseline.
Do not interpret the prepared policy file as evidence that the role has already
been restricted. The updated Beijing manager successfully returned `not_due`
(request `1-6ae2b12b-13614476-49de47de3fdd`) using the existing role permissions.
Local security regression tests and GitHub CI passed (run `40807436066`, including
the clean Node dependency check). DNS staging verification of the candidate did
not produce a retained success result; it must be repeated before cutover.
The last verified public certificate expires 2027-01-27
01:21:23 UTC (09:21:23 Beijing/Singapore).

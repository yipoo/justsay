# JustSay HTTPS certificate automation

This is an independent copy of the MemoryAI Certbot workflow, adapted for:

| Setting | Value |
| --- | --- |
| Domain | `justsay.api.53kj.com` |
| FC region | `cn-beijing` |
| Existing function | `justsay-api` |
| DNS zone | `53kj.com` |
| Validation TXT | `_acme-challenge.justsay.api` |
| Health endpoint | `/health`, expecting `{"ok": true}` |
| Schedule | Daily at 02:37 UTC / 10:37 Singapore |

The workflow runs on GitHub-hosted Ubuntu with Python 3.12. It does not need a
local computer or a separate renewal cloud function. GitHub schedules can be
delayed; they are not an exact-time guarantee.

## Independent state and credentials

The repository has its own concurrency lock, bootstrap secret, encryption key,
and `justsay-api-53kj-com-acme-state-v1` artifact. It does not read or modify the
MemoryAI repository or its certificate state. Only encrypted state is uploaded.
All private keys, cloud keys and local certificate state stay out of Git.

Required repository Secrets:

- `ALIYUN_ACCESS_KEY_ID` and `ALIYUN_ACCESS_KEY_SECRET`: dedicated renewal user.
- `ACME_STATE_ENCRYPTION_KEY`: an independent random encryption secret.
- `ACME_BOOTSTRAP_STATE`: encrypted initial Certbot account and certificate state.

The two ACME secrets can be generated from the existing local JustSay Certbot
configuration with `bootstrap.py`. Set `ACME_STATE_ENCRYPTION_KEY` and
`STATE_ARCHIVE` in the environment, then run:

```sh
python scripts/certificates/bootstrap.py /path/to/justsay-tls/config
```

`STATE_ARCHIVE` must point outside this public repository. Upload its encrypted
contents to `ACME_BOOTSTRAP_STATE` by piping the
file to `gh secret set`; never put plaintext certificate state in the repo.

## Permissions and activation

`cloud-policy.json` describes the intended permissions: read/update the Beijing
custom domain's certificate, plus read/add/delete DNS records in `53kj.com`.
`dns-policy.json` is the DNS-only portion if FC access already exists. DNS
permissions apply to the whole zone; the script restricts writes and cleanup to
the exact JustSay validation hostname and current order value.

Keep `CERT_DNS_AUTOMATION_ENABLED=false` until the dedicated cloud credentials
and policy have been configured. While disabled, the scheduled workflow performs
public HTTPS and health checks only. It does **not** renew or deploy certificates.

After configuring the cloud credentials and permissions:

```sh
gh variable set CERT_DNS_AUTOMATION_ENABLED --body true --repo yipoo/justsay
gh workflow run certificate.yml --repo yipoo/justsay -f staging_test=true
```

Confirm the staging test passes, then run the production check:

```sh
gh workflow run certificate.yml --repo yipoo/justsay
```

The staging run validates DNS against Let's Encrypt's test CA and never deploys
its untrusted certificates. Production runs renew only when Certbot considers
the certificate due. Deployment converts the RSA key to the format FC accepts,
updates only `certConfig`, and checks that routes, authentication, protocol,
TLS settings and WAF settings remain unchanged. Public verification checks the
trusted live certificate, at least 30 days of validity, and API health.

## Public repository scheduling limitation

GitHub automatically disables scheduled workflows in public repositories after
60 days without repository activity. Workflow runs alone should not be relied
on to keep the repository active. Keep the repository maintained and re-enable
the schedule when needed, or move this automation to a private operations
repository for a low-activity service. No artificial keepalive commits are made.
See [GitHub's schedule documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule).

GitHub Actions failure notifications use the repository owner's notification
preferences. Encrypted artifacts are retained for 90 days; the bootstrap secret
provides recovery if no artifact exists. Do not rotate the encryption key without
re-encrypting both stored and bootstrap state.

## Local tests

```sh
pip install -r scripts/certificates/requirements.txt
python -m unittest discover -s scripts/certificates -p 'test_*.py' -v
python scripts/certificates/manage.py verify
```

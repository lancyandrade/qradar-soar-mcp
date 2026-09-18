# Runbook: key rotation

Three secrets exist in a deployment. Rotate each on schedule and immediately
on suspicion. **Rotate first, investigate second**: a rotated key makes a leak
harmless; history rewriting never does.

| Secret | Held by | Rotation trigger |
|---|---|---|
| SOAR API key (`SOAR_API_KEY_ID` / `SOAR_API_KEY_SECRET`) | the MCP server's environment | schedule; any suspected exposure; a person with access leaves |
| Approval signing key (`SOAR_APPROVAL_PRIVATE_KEY_FILE`, Ed25519) | the approver's environment **only** | schedule; approver leaves; private key file touched by anyone else |
| HTTP bearer token (`SOAR_HTTP_AUTH_TOKEN`) | server and its HTTP clients | schedule; any client decommissioned |

## 1. SOAR API key

1. In SOAR, **Administrator Settings → API Keys**, create a new key with the
   same (or narrower) permission set. Record the id; copy the secret once.
2. Update the server's environment (`.env`, the Claude Desktop `env` block,
   or your secret store) with the new id and secret.
3. Restart the server and confirm:
   ```bash
   uv run qradar-soar-mcp --check
   ```
   `ping.ok` must be `true` and `incidents_visible` non-null.
4. Revoke the old key in SOAR. Do this the same day; do not leave two live
   keys "just in case".
5. If the old key was ever written to disk outside the secret store, shred
   that file. If it was ever committed, see §4.

The server never logs the secret: the redaction filter replaces it with
`[REDACTED]` wherever it might appear, and the audit log carries no
credentials. There is nothing to clean in the logs after a rotation.

## 2. Approval signing key (Ed25519)

The server holds only the **public** key. Rotation is therefore a two-sided
change: a new keypair in the approver's environment, and a new public key on
the server.

1. In the approver's environment:
   ```bash
   qradar-soar-approve keygen \
     --private ~/.config/qradar-soar/approval-2026-10.key \
     --public  ~/.config/qradar-soar/approval-2026-10.pub
   ```
   The private key is written with mode `0600`. `keygen` refuses to overwrite
   an existing file.
2. Copy **only** the `.pub` file to the MCP host and point
   `SOAR_APPROVAL_PUBLIC_KEY_FILE` at it. Restart the server. The startup log
   line does not print key material; `--check` reports
   `approvals.can_verify: true` when the key loaded.
3. Any request approved with the old private key is now rejected
   (`DENY_APPROVAL`, signature). Pending requests can simply be re-approved
   with the new key; nothing needs to be reissued because the request file
   is unchanged.
4. Delete the old private key from the approver's environment. Keep the old
   public key only if you need to re-verify old `.approved.json` files for an
   investigation; it can verify but cannot sign.
5. Update `SOAR_APPROVAL_PRIVATE_KEY_FILE` (or `--key`) in the approver's
   shell profile.

Never place the private key on the MCP host. If you find it there, treat it
as compromised and rotate.

## 3. HTTP bearer token

Only if `SOAR_MCP_TRANSPORT=streamable-http`.

1. Generate a new token (32+ random bytes, e.g. `openssl rand -hex 32`).
2. Update every client that connects over HTTP.
3. Set `SOAR_HTTP_AUTH_TOKEN` on the server and restart. There is no
   overlap window: the server accepts exactly one token.
4. The token is compared in constant time and never logged.

## 4. If a secret was committed or leaked

1. **Rotate it now** (§1–3). Everything below is cleanup, not remediation.
2. Confirm what was exposed:
   ```bash
   git log --all --full-history -- .env
   git log -p --all | grep -iE "api_key_secret|BEGIN .*PRIVATE KEY"
   uv run python scripts/check_no_secrets.py
   ```
3. If the secret reached a public remote, assume it was harvested within
   minutes. Revoking the old key in SOAR is the only effective response.
4. Review the audit log for the exposure window:
   ```bash
   uv run qradar-soar-audit verify /var/log/qradar-soar-mcp/audit.jsonl
   ```
   and look for `MUTATION_*` and `APPROVAL_*` records you do not recognise.
   Remember the audit log records what *this server* did with the key, not
   what anyone else did with it: check SOAR's own audit for the key id.
5. Only then rewrite history if you must, and force-push with the whole
   team's agreement. It does not un-leak anything.

## 5. Schedule

| Secret | Suggested cadence |
|---|---|
| SOAR API key | 90 days, or your organisation's service-account policy |
| Approval signing key | 180 days, and whenever the approver set changes |
| HTTP bearer token | 90 days |

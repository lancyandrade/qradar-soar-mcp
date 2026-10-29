# Runbook: key rotation

Three secrets exist in a deployment. Rotate each on schedule and immediately
on suspicion. **Rotate first, investigate second**: a rotated key makes a leak
harmless; history rewriting never does.

| Secret | Held by | Rotation trigger |
|---|---|---|
| SOAR API key (`SOAR_API_KEY_ID` / `SOAR_API_KEY_SECRET`) | the MCP server's environment, one key per instance | schedule; any suspected exposure; a person with access leaves |
| Approval signing key (`SOAR_APPROVAL_PRIVATE_KEY_FILE`, Ed25519) | the approver's environment **only** | schedule; approver leaves; private key file touched by anyone else |
| HTTP bearer token (`SOAR_HTTP_AUTH_TOKEN`) | server and its HTTP clients | schedule; any client decommissioned |

**Every change here needs a server restart.** The server reads its environment and
key files once, at start-up. For a stdio server, restart means restarting the MCP
client that launched it (for example, quit and reopen Claude Desktop), or the process
keeps running with the old values. Only the kill switch (§0) takes effect without a
restart.

With the [recommended two-instance deployment](../../README.md#recommended-deployment-two-instances-two-keys)
each instance has its own key. Rotate them one at a time, and check each instance
afterwards.

## 0. Emergency stop: the kill switch

If a key or the ops instance may be misused, stop mutation **before** you rotate:

```bash
touch /etc/qradar-soar-mcp/ops/HALT     # the instance's SOAR_KILL_SWITCH_FILE
```

From the next tool call on, every Tier ≥1 call is denied (`DENY_KILL_SWITCH`) and
audited; reads continue; no restart is needed. If the server cannot tell whether the
file exists, it treats the switch as engaged. Remove the file to resume. The default
path is the relative `HALT`, resolved against the server's working directory, so set
an absolute `SOAR_KILL_SWITCH_FILE` in advance. `--check` reports
`limits.kill_switch.path` and `limits.kill_switch.active`.

The kill switch stops **this server**. It does nothing about someone else holding the
SOAR key: for that, revoke the key in SOAR (§1, step 4).

## 1. SOAR API key

1. In SOAR, **Administrator Settings → API Keys**, create a new key with the
   same (or narrower) permission set. For the default instance that is a read-only
   permission set. Record the id; copy the secret once.
2. Update the server's environment (`.env`, the MCP client's `env` block,
   or your secret store) with the new id and secret.
3. Restart the server (see above) and confirm with the same environment:
   ```bash
   uv run qradar-soar-mcp --check
   ```
   The exit code must be `0`, `ping.ok` must be `true`, and
   `ping.incidents_visible` must be a number. `capabilities` must still list exactly
   the flags this instance should have. `--check` cannot show which SOAR permissions
   the new key has: verify that in SOAR.
4. Revoke the old key in SOAR. Do this the same day; do not leave two live
   keys "just in case".
5. If the old key was ever written to disk outside the secret store, shred
   that file. That includes an MCP client's configuration file and shell history. If
   the key was ever committed, see §4.

The server never writes the secret it knows: the redaction filter replaces it with
`[REDACTED]` in log lines, errors and tool output, and audit records are redacted the
same way before they are written. There is nothing to clean in this server's logs
after a rotation. Logs from other software in the path (a reverse proxy, a debugging
session) are not covered.

## 2. Approval signing key (Ed25519)

In 0.2.0 no tool asks for an approval (`soar_invoke_action` refuses every call), so
nothing is waiting on a rotation. Keep the keys rotated anyway, so they are sound
when invocation is enabled.

The server holds only the **public** key. Rotation is therefore a two-sided
change: a new keypair in the approver's environment, and a new public key on
the server.

1. In the approver's environment:
   ```bash
   qradar-soar-approve keygen \
     --private ~/.config/qradar-soar/approval-2026-10.key \
     --public  ~/.config/qradar-soar/approval-2026-10.pub
   ```
   On POSIX systems the private key is created with mode `0600`; on Windows, restrict
   the file with an ACL yourself. `keygen` refuses to overwrite an existing file.
2. Copy **only** the `.pub` file to the MCP host and point
   `SOAR_APPROVAL_PUBLIC_KEY_FILE` at it. Restart the server. A key that cannot be
   loaded, or is not Ed25519, makes the server refuse to start. The startup log does
   not print key material; `--check` reports `approvals.can_verify: true` when the key
   loaded.
3. Requests approved with the old key and not yet used are now refused with
   `DENY_APPROVAL` (invalid signature), and `qradar-soar-approve` will not sign them
   again, because they are no longer pending. Ask for the call to be repeated
   **without** its `approval_id`: that creates a new request, which the approver signs
   with the new key. Requests still pending can be approved with the new key as
   usual.
4. Delete the old private key from the approver's environment. Keep the old
   public key only if you need to re-verify old `.approved.json` / `.consumed.json`
   files for an investigation; it can verify but cannot sign.
5. Update `SOAR_APPROVAL_PRIVATE_KEY_FILE` (or `--key`) in the approver's
   shell profile.

Never place the private key on the MCP host, and never set
`SOAR_APPROVAL_PRIVATE_KEY_FILE` in the server's environment. If you find the private
key there, treat it as compromised and rotate.

## 3. HTTP bearer token

Only if `SOAR_MCP_TRANSPORT=streamable-http`.

1. Generate a new token (32+ random bytes, e.g. `openssl rand -hex 32`).
2. Update every client that connects over HTTP.
3. Set `SOAR_HTTP_AUTH_TOKEN` on the server and restart. There is no
   overlap window: the server accepts exactly one token, and a request without it
   gets `401`.
4. The token is compared in constant time and redacted from the server's logs.

## 4. If a secret was committed or leaked

1. **Rotate it now** (§1–3), and engage the kill switch (§0) if the ops instance may
   be involved. Everything below is cleanup, not remediation.
2. Confirm what was exposed:
   ```bash
   git log --all --full-history -- .env
   git log -p --all | grep -iE "api_key_secret|BEGIN .*PRIVATE KEY"
   uv run python scripts/check_no_secrets.py
   ```
3. If the secret reached a public remote, assume it was harvested within
   minutes. Revoking the old key in SOAR is the only effective response.
4. Review the audit log of every instance that held the key, for the exposure window:
   ```bash
   uv run qradar-soar-audit verify /var/log/qradar-soar-mcp/ops/audit.jsonl
   ```
   `verify` exits `1` and names the first broken record if the chain was altered.
   Check the record count it prints: a path that does not exist is reported as
   `OK: 0 records`, so a mistyped path looks like an intact, empty log.
   Then look for `MUTATION_*`, `APPROVAL_*`, `DECISION_DENIED` and `BREAKER_TRIPPED`
   records you do not recognise. The audit log records what *this server* did with
   the key (successful reads are not recorded), not what anyone else did with it:
   check SOAR's own audit for the key id.
5. Only then rewrite history if you must, and force-push with the whole
   team's agreement. It does not un-leak anything.

## 5. Notes on the audit log during maintenance

- Keep `SOAR_AUDIT_LOG_PATH` the same across a restart. The hourly caps are rebuilt
  from that file, and the hash chain continues from its last record. Pointing a
  restarted server at a new, empty file resets both.
- To archive a log, run `qradar-soar-audit verify` on it first, stop the server, move
  the file, and start the server again. It starts a new chain, and its hourly caps
  start from zero, so archive outside busy hours.
- A tripped circuit breaker (`DENY_BREAKER`) is cleared only by a restart. Find out
  why three Tier ≥2 calls failed in a row before restarting.

## 6. Schedule

| Secret | Suggested cadence |
|---|---|
| SOAR API key | 90 days, or your organisation's service-account policy |
| Approval signing key | 180 days, and whenever the approver set changes |
| HTTP bearer token | 90 days |

# Catarina Secrets CLI (`csec`)

Your AI coding agent can use your API keys. It never sees them.

`csec` keeps your secrets in an end-to-end encrypted vault and gives them to your apps and AI agents
only when you approve. Secrets are encrypted on your device before upload; the server stores
ciphertext it cannot read.

> **Early access.** Catarina Secrets is in private testing. You need an invited account to link
> this CLI. Join the waitlist at <https://secret.getcatarina.com>.

## Scan a project for leaked keys (no account needed)

```sh
npx catarina-secrets scan            # files, including git-ignored .env files
npx catarina-secrets scan --history  # also every line ever committed, on all branches
```

`csec scan` runs offline. It finds keys from AWS, GitHub, Stripe, OpenAI, Anthropic, Google, Slack,
SendGrid, npm, Hugging Face and others, private keys, database URLs with passwords, and
random-looking values under secret names. It never prints a full secret, only its first and last
characters. It exits with code 1 when it finds a high-confidence secret, so it works in CI and git
hooks. Add `--json` for machine-readable output and the comment `csec:ignore` to silence a line.

Keys found in git history must be rotated at the provider: deleting a file doesn't remove it from
past commits.

**Block secrets before they're committed** (in each repository):

```sh
csec scan --install-hook     # git pre-commit hook; remove with --uninstall-hook
```

The hook checks only what you're committing. High-confidence secrets block the commit; possible
ones are shown but allowed. It never replaces a pre-commit hook you already have.

**GitHub Actions:**

```yaml
name: Secret scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }   # full history for --history
      - uses: btaskol/catarina-secrets-cli@v1
```

The job fails when a high-confidence secret is found. Set `with: { history: "false" }` to scan only the
current files.

## Requirements

- Node.js 22 or newer
- macOS for Touch ID protection and the MCP server for AI agents
- Linux and Windows: every command except `csec mcp` works; device keys are stored in a file only
  your user can read (`~/.config/catarina`, mode 0600)

## Install and link this computer

```sh
npm install -g catarina-secrets
csec login
```

`csec login` shows a pairing code and a fingerprint. Open your vault at
<https://secret.getcatarina.com/vault/>, choose **Approve a device**, type the code, and approve
only if the fingerprint matches the one in your terminal. On a Mac, the device keys are then sealed
with Touch ID.

## Use secrets in a project

```sh
cd my-app
csec init my-app --env dev          # writes .csec.json (no secrets in it)
csec import .env                    # encrypt an existing .env, then offer to delete it
csec set STRIPE_SECRET_KEY          # or add one at a time (hidden prompt)
csec set SESSION_SECRET --generate  # create a strong random secret without showing it
csec run -- npm run dev             # start your app with the secrets as environment variables
```

`csec list` shows names, `csec get NAME` prints one value, `csec run -e prod -- …` picks another
environment.

## Claude Code

Give Claude Code the MCP server, so it can **use** a key without ever reading it:

```sh
claude mcp add --scope user catarina-secrets -- csec mcp
```

Claude Code then has two tools:

- `list_secrets`: names only, never values.
- `call_api`: makes an HTTPS request with a secret added as a header. The first time a secret is
  used with a host, Touch ID asks you to approve. The approval lasts 15 minutes for that secret and
  host only, and the secret is removed from anything sent back to the agent.

The MCP server refuses to start unless this computer's keys are protected by Touch ID. If you linked
with `--no-touchid`, run `csec logout && csec login`.

**Don't** start the agent itself with `csec run -- claude`: that puts every secret into the agent's
environment, where it can read them. Use `csec run` for your app, and MCP for the agent.

## Cursor

Add the server to `~/.cursor/mcp.json` (all projects) or `.cursor/mcp.json` (one project):

```json
{
  "mcpServers": {
    "catarina-secrets": { "command": "csec", "args": ["mcp"] }
  }
}
```

If Cursor says it can't find `csec`, use the full path from `which csec` as the `command`. Apps
opened from the Dock don't always see your shell's `PATH`.

## Other MCP clients

Any client that runs stdio MCP servers works with the command `csec` and the argument `mcp`.

## Agents without MCP

Create a short-lived grant and run the local proxy:

```sh
csec grant OPENAI_API_KEY --host api.openai.com --for 15m
csec proxy
```

`csec grant` prints two values for the agent, `CATARINA_BASE_URL` (the local proxy plus the grant ID)
and `CATARINA_GRANT_TOKEN` (shown once). The agent calls `$CATARINA_BASE_URL/<api-path>` with
`Authorization: Bearer $CATARINA_GRANT_TOKEN`, and the broker adds the real key only for `api.openai.com`. `csec grants` lists grants and `csec revoke <id>` ends one early.

## Security

- Secrets are encrypted with AES-256-GCM on your devices. The vault key is unlocked by a passkey or
  your recovery key, never by anything the server holds.
- Each CLI request is signed with this computer's Ed25519 key; replays are rejected.
- Broker calls are the one exception to "the server never sees a secret": it is decrypted in memory
  for that single request, sent only to the pinned host, and never stored.

## All commands

Run `csec help`.

## Source

The CLI's source is at <https://github.com/btaskol/catarina-secrets-cli>. Run the scanner's tests with
`npm test` (Node.js 22 or newer).

## License

The `csec` CLI is MIT licensed. Report security issues to security@getcatarina.com, not in a public
issue.

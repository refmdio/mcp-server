# RefMD MCP Server

A Model Context Protocol server that exposes RefMD documents over a hosted SSE endpoint, so chatbots can browse and edit Markdown through RefMD's API.

## Features

- Streamable HTTP/SSE transport compatible with hosted MCP clients (e.g. Claude, Cursor)
- Resource template `refmd://document/{id}` to read document Markdown and metadata
- Tools for listing, searching, creating, and updating documents via the RefMD API

## Prerequisites

- Node.js 18+
- Access to an existing RefMD instance
- Either a personal access token (JWT) or credentials that can log in via `/api/auth/login`

## Configuration

The server now authenticates users via OAuth 2.1 with PKCE. Configure it with the following variables:

| Variable | Description |
| --- | --- |
| `REFMD_API_BASE` | **Required.** Base URL of your RefMD API (e.g. `https://refmd.example.com`). |
| `OAUTH_CLIENT_IDS` | Comma-separated list of allowed `client_id` values. Leave empty to allow any. |
| `OAUTH_ALLOWED_REDIRECTS` | Comma-separated list of allowed redirect URIs. Defaults to allowing HTTPS URLs and `http://localhost`. Include ChatGPT’s callback URL (`https://chat.openai.com/aip/mcp/oauth/callback`). |
| `OAUTH_ISSUER` | Optional public issuer URL (defaults to the current request origin). |
| `ACCESS_TOKEN_TTL_SECONDS` | Optional access-token lifetime (default `3600`). |
| `REFRESH_TOKEN_TTL_SECONDS` | Optional refresh-token lifetime (default `2592000`, i.e. 30 days). |
| `MCP_DB_DRIVER` | Optional. Set to `sqlite`, `postgres`, or `mysql` to persist OAuth tokens. Defaults to in-memory storage. |
| `MCP_DB_URL` | Optional connection string for the configured driver (e.g. `postgres://user:pass@host/db`). For SQLite you may omit this and use `MCP_DB_SQLITE_PATH`. |
| `MCP_DB_SQLITE_PATH` | Optional filesystem path for SQLite storage (defaults to `./data/refmd-mcp.sqlite`). Accepts plain paths or `file:///` URLs. |
| `PORT` / `HOST` | Optional listen port / host (defaults: `3334` / `0.0.0.0`). |

> ℹ️ Install the appropriate database driver when enabling persistence:  
> `npm install better-sqlite3` for SQLite, `npm install pg` for PostgreSQL, or `npm install mysql2` for MySQL/MariaDB.

## Install & Build

```bash
cd mcp-server
npm install
npm run build
```

## Run

```bash
npm start
REFMD_API_BASE="https://refmd.example.com" \
OAUTH_CLIENT_IDS="chatgpt-connector" \
OAUTH_ALLOWED_REDIRECTS="https://chat.openai.com/aip/mcp/oauth/callback" \
npm start
```

The server exposes two transports:

- `http://<host>:<port>/sse` — SSE transport (compatible with Claude SSE etc.)
- `http://<host>:<port>/mcp` — Streamable HTTP transport (one-shot POST per exchange)

## OAuth flow

1. Configure your client (e.g. ChatGPT custom connector) with:
   - **Authorization URL:** `https://your-domain.example.com/oauth/authorize`
   - **Token URL:** `https://your-domain.example.com/oauth/token`
   - **Revocation URL:** `https://your-domain.example.com/oauth/revoke`
   - **Scopes:** (leave blank)
   - **PKCE:** enabled (ChatGPT uses S256 automatically)
2. When prompted, the browser shows the RefMD MCP consent page. Paste a RefMD API token generated from **Profile → API tokens** and approve.
3. The connector receives an access token and can call `/sse` or `/mcp` with `Authorization: Bearer <token>`.

Tokens can be revoked from RefMD (profile page) or via `POST /oauth/revoke`.

## Run with Docker

```bash
# Build image
docker build -t refmd-mcp .

docker run -p 3334:3334 \
  -e REFMD_API_BASE="https://refmd.example.com" \
  -e OAUTH_CLIENT_IDS="chatgpt-connector" \
  -e OAUTH_ALLOWED_REDIRECTS="https://chat.openai.com/aip/mcp/oauth/callback" \
  -e MCP_DB_DRIVER="sqlite" \
  -e MCP_DB_SQLITE_PATH="/data/refmd-mcp.sqlite" \
  refmd-mcp
```

## Connecting a Chat Client

- **Claude (CLI):**
  ```bash
  claude mcp add --transport sse refmd https://your-domain.example.com/sse
  ```
- **Cursor / VS Code / MCP Inspector:** choose an SSE transport and supply the same URL.

Once connected, resources appear under `refmd://document/{id}`. Available tools include `refmd-list-documents`, `refmd-search-documents`, `refmd-create-document`, `refmd-read-document`, `refmd-update-document-content`, and more.

## Release workflow

The GitHub Actions workflow `CI MCP Server` ships the container image. It runs automatically on pushes/PRs touching `mcp-server` and publishes to GHCR when:

- the push is a tag matching `mcp-server-v*` (versioned release), or
- the workflow is manually triggered with `publish=true`.

Tags published to `ghcr.io/<owner>/refmd-mcp` include semantic versions (`1.2.0`, `1.2`, `1`), the raw git tag, and `latest`. Use the `extra-tag` input for additional labels when invoking the workflow manually.

## Development

Run in watch mode with TSX:

```bash
npm run dev
```

Any code changes require a rebuild (`npm run build`) before deploying or running with `npm start`.

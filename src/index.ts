import express, {
  type NextFunction,
  type Request,
  type Response as ExpressResponse,
} from 'express';
import crypto from 'node:crypto';
import { z } from 'zod';
import { McpServer, ResourceTemplate } from '@modelcontextprotocol/sdk/server/mcp.js';
import { SSEServerTransport } from '@modelcontextprotocol/sdk/server/sse.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { createTokenStore, TokenStore } from './tokenStore.js';
import {
  RefMDUser,
  StoredAccessToken,
  StoredAuthorizationCode,
  StoredRefreshToken,
} from './types.js';

const app = express();
app.disable('x-powered-by');
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: false }));

function getClientIp(req: Request): string {
  const forwarded = req.headers['x-forwarded-for'];
  if (typeof forwarded === 'string' && forwarded.trim() !== '') {
    const first = forwarded
      .split(',')
      .map((value) => value.trim())
      .find((value) => value.length > 0);
    if (first) {
      return first;
    }
  } else if (Array.isArray(forwarded) && forwarded.length > 0) {
    const first = forwarded
      .map((value) => value.trim())
      .find((value) => value.length > 0);
    if (first) {
      return first;
    }
  }
  return req.socket.remoteAddress ?? '-';
}

type LogFields = Record<string, unknown>;
type LogLevel = 'info' | 'warn' | 'error';

function logWithLevel(level: LogLevel, req: Request, message: string, fields?: LogFields): void {
  const consoleMethod =
    level === 'error' ? console.error : level === 'warn' ? console.warn : console.log;
  const context = `${req.method} ${req.originalUrl} from ${getClientIp(req)}`;
  if (fields) {
    consoleMethod(`[${level}] ${message} — ${context}`, fields);
  } else {
    consoleMethod(`[${level}] ${message} — ${context}`);
  }
}

const logInfo = (req: Request, message: string, fields?: LogFields): void =>
  logWithLevel('info', req, message, fields);
const logWarn = (req: Request, message: string, fields?: LogFields): void =>
  logWithLevel('warn', req, message, fields);
const logError = (req: Request, message: string, fields?: LogFields): void =>
  logWithLevel('error', req, message, fields);

function maskSecret(value?: string | null): string | undefined {
  if (!value) return undefined;
  const trimmed = value.trim();
  if (!trimmed) return undefined;
  if (trimmed.length <= 8) {
    return `${trimmed.slice(0, 2)}…`;
  }
  return `${trimmed.slice(0, 4)}…${trimmed.slice(-4)}`;
}

app.use((req: Request, res: ExpressResponse, next: NextFunction) => {
  const start = Date.now();
  const remote = getClientIp(req);
  console.log(`[request] ${remote} ${req.method} ${req.originalUrl}`);
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(
      `[response] ${remote} ${req.method} ${req.originalUrl} -> ${res.statusCode} (${duration}ms)`,
    );
  });
  next();
});

app.use((req: Request, res: ExpressResponse, next: NextFunction) => {
  res.header('Access-Control-Allow-Origin', '*');
  res.header(
    'Access-Control-Allow-Headers',
    'Content-Type, Authorization, MCP-Session-Id',
  );
  res.header('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }
  next();
});

type DocumentState = 'active' | 'archived' | 'all';

type RefMDDocument = {
  id: string;
  title: string;
  parent_id: string | null;
  type: string;
  created_at: string;
  updated_at: string;
  path: string | null;
  archived_at: string | null;
  archived_by: string | null;
  archived_parent_id: string | null;
};

type DocumentListResponse = {
  items: RefMDDocument[];
};

type DocumentContentResponse = {
  content?: string | null;
};

type SearchResult = {
  id: string;
  title: string;
  document_type: string;
  path?: string | null;
  updated_at: string;
};

type BacklinkInfo = {
  document_id: string;
  title: string;
  document_type: string;
  file_path?: string | null;
  link_type: string;
  link_text?: string | null;
  link_count: number;
};

type BacklinkResponse = {
  backlinks: BacklinkInfo[];
  total_count: number;
};

type OutgoingLink = {
  document_id: string;
  title: string;
  document_type: string;
  file_path?: string | null;
  link_type: string;
  link_text?: string | null;
  position_start?: number | null;
  position_end?: number | null;
};

type OutgoingLinksResponse = {
  links: OutgoingLink[];
  total_count: number;
};

type SnapshotSummary = {
  id: string;
  document_id: string;
  label: string;
  notes?: string | null;
  kind: string;
  created_at: string;
  created_by?: string | null;
  byte_size: number;
  content_hash: string;
};

type SnapshotListResponse = {
  items: SnapshotSummary[];
};

type SnapshotDiffSide = {
  kind: 'current' | 'snapshot';
  markdown: string;
  snapshot?: SnapshotSummary | null;
};

type SnapshotDiffResponse = {
  base: SnapshotDiffSide;
  target: SnapshotDiffSide;
  diff: unknown;
};

type SnapshotRestoreResponse = {
  snapshot: SnapshotSummary;
};

type ShareItem = {
  id: string;
  token: string;
  permission: string;
  expires_at?: string | null;
  url: string;
  scope: string;
  parent_share_id?: string | null;
};

type CreateShareResponse = {
  token: string;
  url: string;
};

type ApplicableShareItem = {
  token: string;
  permission: string;
  scope: string;
  excluded: boolean;
};

type TagItem = {
  name: string;
  count: number;
};

type RefMDConfig = {
  baseUrl: string;
  token: string;
};

class RefMDClient {
  private baseUrl: URL;
  private token: string;

  constructor(config: RefMDConfig) {
    this.baseUrl = new URL(config.baseUrl);
    const trimmed = config.token.trim();
    if (!trimmed) {
      throw new Error('RefMD API token required');
    }
    this.token = trimmed;
  }

  async listDocuments(params: {
    query?: string;
    tag?: string;
    state?: DocumentState;
  }): Promise<DocumentListResponse> {
    const url = this.buildUrl('/api/documents', {
      query: params.query ?? undefined,
      tag: params.tag ?? undefined,
      state: params.state ?? undefined,
    });
    return this.request<DocumentListResponse>(url, { method: 'GET' });
  }

  async getDocument(id: string): Promise<RefMDDocument> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}`);
    return this.request<RefMDDocument>(url, { method: 'GET' });
  }

  async getDocumentContent(id: string): Promise<string> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/content`);
    const res = await this.request<DocumentContentResponse>(url, {
      method: 'GET',
    });
    return res.content ?? '';
  }

  async searchDocuments(query: string): Promise<SearchResult[]> {
    const url = this.buildUrl('/api/documents/search', { q: query });
    return this.request<SearchResult[]>(url, { method: 'GET' });
  }

  async createDocument(params: {
    title?: string | null;
    parentId?: string | null;
    type?: 'document' | 'folder';
  }): Promise<RefMDDocument> {
    const url = this.buildUrl('/api/documents');
    return this.request<RefMDDocument>(url, {
      method: 'POST',
      body: JSON.stringify({
        title: params.title ?? undefined,
        parent_id: params.parentId ?? null,
        type: params.type ?? undefined,
      }),
    });
  }

  async updateDocumentContent(id: string, content: string): Promise<RefMDDocument> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/content`);
    return this.request<RefMDDocument>(url, {
      method: 'PUT',
      body: JSON.stringify({ content }),
    });
  }

  async updateDocument(params: {
    id: string;
    title?: string;
    parentId?: string | null;
  }): Promise<RefMDDocument> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(params.id)}`);
    const body: Record<string, unknown> = {};
    if (Object.prototype.hasOwnProperty.call(params, 'title')) {
      body.title = params.title;
    }
    if (Object.prototype.hasOwnProperty.call(params, 'parentId')) {
      body.parent_id = params.parentId ?? null;
    }
    return this.request<RefMDDocument>(url, {
      method: 'PATCH',
      body: JSON.stringify(body),
    });
  }

  async archiveDocument(id: string): Promise<RefMDDocument> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/archive`);
    return this.request<RefMDDocument>(url, { method: 'POST' });
  }

  async unarchiveDocument(id: string): Promise<RefMDDocument> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/unarchive`);
    return this.request<RefMDDocument>(url, { method: 'POST' });
  }

  async deleteDocument(id: string): Promise<void> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}`);
    await this.request(url, { method: 'DELETE' });
  }

  async listBacklinks(id: string): Promise<BacklinkResponse> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/backlinks`);
    return this.request<BacklinkResponse>(url, { method: 'GET' });
  }

  async listOutgoingLinks(id: string): Promise<OutgoingLinksResponse> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/links`);
    return this.request<OutgoingLinksResponse>(url, { method: 'GET' });
  }

  async listSnapshots(id: string, params?: { token?: string; limit?: number; offset?: number }): Promise<SnapshotListResponse> {
    const url = this.buildUrl(`/api/documents/${encodeURIComponent(id)}/snapshots`, {
      token: params?.token,
      limit: params?.limit !== undefined ? String(params.limit) : undefined,
      offset: params?.offset !== undefined ? String(params.offset) : undefined,
    });
    return this.request<SnapshotListResponse>(url, { method: 'GET' });
  }

  async getSnapshotDiff(params: {
    documentId: string;
    snapshotId: string;
    token?: string;
    compareSnapshotId?: string;
    base?: 'auto' | 'current' | 'previous';
  }): Promise<SnapshotDiffResponse> {
    const url = this.buildUrl(
      `/api/documents/${encodeURIComponent(params.documentId)}/snapshots/${encodeURIComponent(params.snapshotId)}/diff`,
      {
        token: params.token,
        compare: params.compareSnapshotId,
        base: params.base,
      },
    );
    return this.request<SnapshotDiffResponse>(url, { method: 'GET' });
  }

  async restoreSnapshot(params: {
    documentId: string;
    snapshotId: string;
    token?: string;
  }): Promise<SnapshotRestoreResponse> {
    const url = this.buildUrl(
      `/api/documents/${encodeURIComponent(params.documentId)}/snapshots/${encodeURIComponent(params.snapshotId)}/restore`,
      {
        token: params.token,
      },
    );
    return this.request<SnapshotRestoreResponse>(url, { method: 'POST' });
  }

  async createShare(params: {
    documentId: string;
    permission?: string;
    expires_at?: string;
  }): Promise<CreateShareResponse> {
    const url = this.buildUrl('/api/shares');
    return this.request<CreateShareResponse>(url, {
      method: 'POST',
      body: JSON.stringify({
        document_id: params.documentId,
        permission: params.permission,
        expires_at: params.expires_at,
      }),
    });
  }

  async listDocumentShares(id: string): Promise<ShareItem[]> {
    const url = this.buildUrl(`/api/shares/documents/${encodeURIComponent(id)}`);
    return this.request<ShareItem[]>(url, { method: 'GET' });
  }

  async deleteShare(token: string): Promise<void> {
    const url = this.buildUrl(`/api/shares/${encodeURIComponent(token)}`);
    await this.request(url, { method: 'DELETE' });
  }

  async listApplicableShares(documentId: string): Promise<ApplicableShareItem[]> {
    const url = this.buildUrl('/api/shares/applicable', { doc_id: documentId });
    return this.request<ApplicableShareItem[]>(url, { method: 'GET' });
  }

  async listTags(filter?: { query?: string }): Promise<TagItem[]> {
    const url = this.buildUrl('/api/tags', { q: filter?.query });
    return this.request<TagItem[]>(url, { method: 'GET' });
  }

  private buildUrl(
    path: string,
    query?: Record<string, string | undefined>,
  ): URL {
    const url = new URL(path, this.baseUrl);
    if (query) {
      for (const [key, value] of Object.entries(query)) {
        if (typeof value === 'string' && value.trim() !== '') {
          url.searchParams.set(key, value);
        }
      }
    }
    return url;
  }

  private async request<T>(url: URL, init: RequestInit): Promise<T> {
    const headers = new Headers(init.headers ?? {});
    if (this.token) {
      headers.set('Authorization', `Bearer ${this.token}`);
    }
    if (init.body && !headers.has('Content-Type')) {
      headers.set('Content-Type', 'application/json');
    }

    const response = await fetch(url, {
      ...init,
      headers,
    });

    if (!response.ok) {
      const detail = await safeReadError(response);
      throw new Error(
        `RefMD API request failed (${response.status} ${response.statusText}): ${detail}`,
      );
    }

    if (response.status === 204) {
      return undefined as T;
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (contentType.includes('application/json')) {
      return (await response.json()) as T;
    }
    const text = await response.text();
    return text as T;
  }
}

// Helpers --------------------------------------------------------------------

async function safeReadError(res: globalThis.Response): Promise<string> {
  try {
    const text = await res.text();
    return text || 'No response body';
  } catch {
    return 'Unable to read error response';
  }
}

function formatDocuments(docs: RefMDDocument[]): string {
  if (docs.length === 0) {
    return 'No documents found.';
  }
  return docs
    .map((doc) => {
      const path = doc.path ? ` (${doc.path})` : '';
      const status = doc.archived_at ? 'archived' : 'active';
      return `- ${doc.title}${path} — id: ${doc.id} [${status}]`;
    })
    .join('\n');
}

function formatSearch(results: SearchResult[]): string {
  if (results.length === 0) {
    return 'No matches.';
  }
  return results
    .map((hit) => {
      const path = hit.path ? ` (${hit.path})` : '';
      return `- ${hit.title}${path} — id: ${hit.id} [${hit.document_type}]`;
    })
    .join('\n');
}

function formatBacklinksList(response: BacklinkResponse): string {
  if (response.total_count === 0 || response.backlinks.length === 0) {
    return 'No backlinks found.';
  }
  return response.backlinks
    .map((item) => {
      const path = item.file_path ? ` (${item.file_path})` : '';
      const text = item.link_text ? ` — text: "${item.link_text}"` : '';
      return `- ${item.title}${path} — id: ${item.document_id} [${item.link_type}] (links: ${item.link_count})${text}`;
    })
    .join('\n');
}

function formatOutgoingLinksList(response: OutgoingLinksResponse): string {
  if (response.total_count === 0 || response.links.length === 0) {
    return 'No outgoing links.';
  }
  return response.links
    .map((item) => {
      const path = item.file_path ? ` (${item.file_path})` : '';
      const text = item.link_text ? ` — text: "${item.link_text}"` : '';
      return `- ${item.title}${path} — id: ${item.document_id} [${item.link_type}]${text}`;
    })
    .join('\n');
}

function formatSnapshotsList(items: SnapshotSummary[]): string {
  if (items.length === 0) {
    return 'No snapshots found.';
  }
  return items
    .map((snapshot) => {
      const notes = snapshot.notes ? ` — notes: ${snapshot.notes}` : '';
      return `- ${snapshot.label} (${snapshot.kind}) — id: ${snapshot.id}, created ${snapshot.created_at}${notes}`;
    })
    .join('\n');
}

function formatSharesList(items: ShareItem[]): string {
  if (items.length === 0) {
    return 'No active share links.';
  }
  return items
    .map((share) => {
      const expires = share.expires_at ? `, expires ${share.expires_at}` : '';
      const scope = share.scope ? ` [${share.scope}]` : '';
      return `- token: ${share.token}${scope} — permission: ${share.permission}${expires}`;
    })
    .join('\n');
}

function formatApplicableShares(items: ApplicableShareItem[]): string {
  if (items.length === 0) {
    return 'No shares apply to this document.';
  }
  return items
    .map((share) => {
      const excluded = share.excluded ? ' (excluded)' : '';
      return `- token: ${share.token} [${share.scope}] — ${share.permission}${excluded}`;
    })
    .join('\n');
}

function formatTags(tags: TagItem[]): string {
  if (tags.length === 0) {
    return 'No tags found.';
  }
  return tags
    .map((tag) => `- ${tag.name} (${tag.count})`)
    .join('\n');
}

async function fetchCurrentUser(baseUrl: string, token: string): Promise<RefMDUser> {
  const url = new URL('/api/auth/me', baseUrl);
  const response = await fetch(url, {
    method: 'GET',
    headers: {
      Authorization: `Bearer ${token}`,
      'Content-Type': 'application/json',
    },
  });
  if (!response.ok) {
    const detail = await safeReadError(response);
    throw new Error(`Token validation failed (${response.status}): ${detail}`);
  }
  const data = (await response.json()) as { id: string; email: string; name: string };
  return {
    id: data.id,
    email: data.email,
    name: data.name,
  };
}

const DEFAULT_ACCESS_TOKEN_TTL_SECONDS = 3600;
const DEFAULT_REFRESH_TOKEN_TTL_SECONDS = 60 * 60 * 24 * 30;

function parseDurationEnv(value: string | undefined, fallbackSeconds: number, envVar: string): number {
  if (value === undefined) {
    return fallbackSeconds;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return fallbackSeconds;
  }
  const parsed = Number.parseInt(trimmed, 10);
  if (!Number.isFinite(parsed) || parsed <= 0) {
    console.warn(
      `${envVar} is invalid ("${value}"); using default of ${fallbackSeconds} seconds.`,
    );
    return fallbackSeconds;
  }
  return parsed;
}

// Configuration ---------------------------------------------------------------

const configSchema = z.object({
  baseUrl: z.string().url(),
  allowedClientIds: z
    .string()
    .transform((value) =>
      value
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    )
    .optional(),
  allowedRedirects: z
    .string()
    .transform((value) =>
      value
        .split(',')
        .map((item) => item.trim())
        .filter((item) => item.length > 0),
    )
    .optional(),
  accessTokenTtlSeconds: z
    .string()
    .optional()
    .transform((value) =>
      parseDurationEnv(value, DEFAULT_ACCESS_TOKEN_TTL_SECONDS, 'ACCESS_TOKEN_TTL_SECONDS'),
    ),
  refreshTokenTtlSeconds: z
    .string()
    .optional()
    .transform((value) =>
      parseDurationEnv(value, DEFAULT_REFRESH_TOKEN_TTL_SECONDS, 'REFRESH_TOKEN_TTL_SECONDS'),
    ),
  dbDriver: z.string().optional(),
  dbUrl: z.string().optional(),
  dbSqlitePath: z.string().optional(),
});

const parsedConfig = configSchema.safeParse({
  baseUrl: process.env.REFMD_API_BASE,
  allowedClientIds: process.env.OAUTH_CLIENT_IDS ?? '',
  allowedRedirects: process.env.OAUTH_ALLOWED_REDIRECTS ?? '',
  accessTokenTtlSeconds: process.env.ACCESS_TOKEN_TTL_SECONDS,
  refreshTokenTtlSeconds: process.env.REFRESH_TOKEN_TTL_SECONDS,
  dbDriver: process.env.MCP_DB_DRIVER,
  dbUrl: process.env.MCP_DB_URL ?? process.env.DATABASE_URL,
  dbSqlitePath: process.env.MCP_DB_SQLITE_PATH,
});

if (!parsedConfig.success) {
  console.error('Invalid configuration:', parsedConfig.error.flatten().fieldErrors);
  process.exit(1);
}

const {
  baseUrl,
  allowedClientIds = [],
  allowedRedirects = [],
  accessTokenTtlSeconds,
  refreshTokenTtlSeconds,
  dbDriver,
  dbUrl,
  dbSqlitePath,
} = parsedConfig.data;

const BASE_URL = baseUrl;
const ACCESS_TOKEN_TTL_MS = Math.max(accessTokenTtlSeconds, 60) * 1000;
const REFRESH_TOKEN_TTL_MS = Math.max(refreshTokenTtlSeconds, 60) * 1000;
const AUTH_CODE_TTL_MS = 5 * 60 * 1000;

const packageVersion = process.env.npm_package_version ?? '0.1.0';

type SupportedDbDriver = 'sqlite' | 'postgres' | 'mysql';
const normalizedDriver = dbDriver?.trim().toLowerCase() as SupportedDbDriver | undefined;
if (dbDriver && !['sqlite', 'postgres', 'mysql'].includes(normalizedDriver ?? '')) {
  console.error(
    `Unsupported MCP_DB_DRIVER value: ${dbDriver}. Expected one of sqlite, postgres, mysql.`,
  );
  process.exit(1);
}

const tokenStore: TokenStore = await createTokenStore(
  normalizedDriver
    ? {
        driver: normalizedDriver,
        url: dbUrl ?? undefined,
        sqlitePath: dbSqlitePath ?? undefined,
      }
    : undefined,
);
if (normalizedDriver) {
  console.log(`Token storage: using ${normalizedDriver} via Kysely.`);
} else {
  console.warn(
    'Token storage: in-memory only. Configure MCP_DB_DRIVER to persist tokens across restarts.',
  );
}

// OAuth storage ---------------------------------------------------------------

const allowedClientIdSet = new Set(allowedClientIds);
const allowedRedirectSet = new Set(allowedRedirects);
const registeredClients = new Map<string, Set<string>>();
const SUPPORTED_SCOPES = ['refmd.read', 'refmd.write'] as const;
const SUPPORTED_SCOPE_STRING = SUPPORTED_SCOPES.join(' ');
const OAUTH_PROTECTED_RESOURCE_BASE_PATH = '/.well-known/oauth-protected-resource';

function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('base64url');
}

function parseScopes(scope?: string): string[] {
  if (!scope) return [];
  return scope
    .split(/\s+/)
    .map((item) => item.trim())
    .filter((item) => item.length > 0);
}

function rememberClientRegistration(clientId: string, redirectUris: string[]): void {
  if (!registeredClients.has(clientId)) {
    registeredClients.set(clientId, new Set<string>());
  }
  const redirectSet = registeredClients.get(clientId)!;
  for (const uri of redirectUris) {
    redirectSet.add(uri);
  }
}

function isClientAllowed(clientId: string): boolean {
  if (registeredClients.has(clientId)) {
    return true;
  }
  return allowedClientIdSet.size === 0 || allowedClientIdSet.has(clientId);
}

function isRedirectUriSafe(uri: string): boolean {
  if (allowedRedirectSet.size > 0 && !allowedRedirectSet.has(uri)) {
    return false;
  }
  try {
    const parsed = new URL(uri);
    if (parsed.protocol === 'https:') return true;
    if (
      parsed.protocol === 'http:' &&
      (parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1')
    ) {
      return true;
    }
  } catch (error) {
    return false;
  }
  return false;
}

function isRedirectAllowed(uri: string, clientId?: string): boolean {
  if (!isRedirectUriSafe(uri)) {
    return false;
  }
  if (!clientId) {
    return true;
  }
  const registered = registeredClients.get(clientId);
  if (!registered || registered.size === 0) {
    return true;
  }
  return registered.has(uri);
}

function hashCodeVerifier(verifier: string): string {
  const digest = crypto.createHash('sha256').update(verifier).digest();
  return digest.toString('base64url');
}

async function storeAuthorizationCode(code: string, record: StoredAuthorizationCode): Promise<void> {
  await tokenStore.saveAuthorizationCode(code, record);
}

async function consumeAuthorizationCode(code: string): Promise<StoredAuthorizationCode | null> {
  return tokenStore.consumeAuthorizationCode(code);
}

async function issueTokens(params: {
  clientId: string;
  refmdToken: string;
  user: RefMDUser;
  scope: string[];
  generateRefresh: boolean;
}): Promise<{ access: StoredAccessToken; refreshToken?: StoredRefreshToken }> {
  const accessToken = randomToken(48);
  const accessRecord: StoredAccessToken = {
    accessToken,
    clientId: params.clientId,
    refmdToken: params.refmdToken,
    user: params.user,
    scope: params.scope,
    expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
  };

  let refreshRecord: StoredRefreshToken | undefined;
  if (params.generateRefresh) {
    const refreshToken = randomToken(64);
    refreshRecord = {
      refreshToken,
      clientId: params.clientId,
      refmdToken: params.refmdToken,
      user: params.user,
      scope: params.scope,
      expiresAt: Date.now() + REFRESH_TOKEN_TTL_MS,
    };
    accessRecord.refreshToken = refreshToken;
    await tokenStore.saveRefreshToken(refreshRecord);
  }

  await tokenStore.saveAccessToken(accessRecord);

  return { access: accessRecord, refreshToken: refreshRecord };
}

async function pruneAccessTokensByRefresh(refreshToken: string): Promise<void> {
  await tokenStore.deleteAccessTokensByRefreshToken(refreshToken);
}

async function getAccessTokenRecord(token: string): Promise<StoredAccessToken | null> {
  const record = await tokenStore.getAccessToken(token);
  if (!record) {
    return null;
  }
  if (record.expiresAt > Date.now()) {
    return record;
  }
  const refreshToken = record.refreshToken;
  if (!refreshToken) {
    await tokenStore.deleteAccessToken(token);
    return null;
  }
  const refreshRecord = await tokenStore.getRefreshToken(refreshToken);
  if (!refreshRecord) {
    await tokenStore.deleteAccessToken(token);
    return null;
  }
  if (refreshRecord.expiresAt <= Date.now()) {
    await tokenStore.deleteAccessToken(token);
    await tokenStore.deleteRefreshToken(refreshRecord.refreshToken);
    return null;
  }
  const renewed: StoredAccessToken = {
    ...record,
    expiresAt: Date.now() + ACCESS_TOKEN_TTL_MS,
  };
  await tokenStore.saveAccessToken(renewed);
  return renewed;
}

async function getRefreshTokenRecord(token: string): Promise<StoredRefreshToken | null> {
  const record = await tokenStore.getRefreshToken(token);
  if (!record) {
    return null;
  }
  if (record.expiresAt > Date.now()) {
    return record;
  }
  await tokenStore.deleteRefreshToken(token);
  await tokenStore.deleteAccessTokensByRefreshToken(token);
  return null;
}

function extractBearerToken(req: Request): string | null {
  const auth = req.headers.authorization;
  if (!auth) return null;
  const match = auth.match(/^Bearer\s+(.+)$/i);
  if (!match) return null;
  return match[1].trim();
}

type ResourceMetadataInfo = {
  issuer: string;
  resourcePath: string;
  resource: string;
  metadataPath: string;
  metadataUrl: string;
};

function normalizeResourcePath(path?: string | null): string {
  if (!path) return '';
  const trimmed = path.trim();
  if (trimmed === '' || trimmed === '/') {
    return '';
  }
  const ensured = trimmed.startsWith('/') ? trimmed : `/${trimmed}`;
  const withoutTrailing = ensured.replace(/\/+$/, '');
  return withoutTrailing === '/' ? '' : withoutTrailing;
}

function buildResourceMetadataInfo(req: Request, resourcePathOverride?: string): ResourceMetadataInfo {
  const resourcePath = normalizeResourcePath(resourcePathOverride ?? req.path);
  const issuer = issuerFromRequest(req);
  const metadataPath =
    resourcePath.length > 0
      ? `${OAUTH_PROTECTED_RESOURCE_BASE_PATH}${resourcePath}`
      : OAUTH_PROTECTED_RESOURCE_BASE_PATH;
  const metadataUrl = `${issuer}${metadataPath}`;
  const resource = resourcePath.length > 0 ? `${issuer}${resourcePath}` : issuer;
  return { issuer, resourcePath, resource, metadataPath, metadataUrl };
}

function resolveResourcePathFromMetadataRequest(path: string): string {
  if (path.startsWith('/mcp/.well-known/oauth-protected-resource')) {
    const suffix = path.slice('/mcp/.well-known/oauth-protected-resource'.length);
    const normalizedSuffix = normalizeResourcePath(suffix);
    return normalizedSuffix ? `/mcp${normalizedSuffix}` : '/mcp';
  }
  const suffix = path.slice(OAUTH_PROTECTED_RESOURCE_BASE_PATH.length);
  return normalizeResourcePath(suffix);
}

function sendUnauthorized(req: Request, res: ExpressResponse, message = 'invalid_token'): void {
  logWarn(req, 'unauthorized request', { error: message });
  const { metadataUrl } = buildResourceMetadataInfo(req);
  const challengeParts = [
    'Bearer realm="refmd-mcp"',
    `error="${message}"`,
    `scope="${SUPPORTED_SCOPE_STRING}"`,
  ];
  if (metadataUrl) {
    challengeParts.push(`resource_metadata="${metadataUrl}"`);
  }
  res.status(401).set('WWW-Authenticate', challengeParts.join(', ')).json({ error: message });
}

const REQUIRED_STREAMABLE_ACCEPT_TYPES = ['application/json', 'text/event-stream'];

function normalizeAcceptHeaderForStreamableTransport(req: Request): void {
  const rawHeader = req.headers.accept;
  if (!rawHeader) {
    req.headers.accept = REQUIRED_STREAMABLE_ACCEPT_TYPES.join(', ');
    return;
  }

  const values: string[] = Array.isArray(rawHeader)
    ? rawHeader.flatMap((value) => value.split(','))
    : rawHeader.split(',');

  const seen = new Map<string, string>();
  for (const value of values) {
    const trimmed = value.trim();
    if (!trimmed) continue;
    const lower = trimmed.toLowerCase();
    if (!seen.has(lower)) {
      seen.set(lower, trimmed);
    }
  }

  for (const required of REQUIRED_STREAMABLE_ACCEPT_TYPES) {
    const lower = required.toLowerCase();
    if (!seen.has(lower)) {
      seen.set(lower, required);
    }
  }

  req.headers.accept = Array.from(seen.values()).join(', ');
}

function firstString(value: unknown): string | undefined {
  if (typeof value === 'string') return value;
  if (Array.isArray(value) && value.length > 0 && typeof value[0] === 'string') {
    return value[0];
  }
  return undefined;
}

function validateClientAndRedirect(clientId: string, redirectUri: string): {
  ok: boolean;
  error?: string;
} {
  if (!clientId) {
    return { ok: false, error: 'invalid_client' };
  }
  if (!isClientAllowed(clientId)) {
    return { ok: false, error: 'unauthorized_client' };
  }
  if (!redirectUri) {
    return { ok: false, error: 'invalid_request' };
  }
  if (!isRedirectAllowed(redirectUri, clientId)) {
    return { ok: false, error: 'invalid_redirect_uri' };
  }
  return { ok: true };
}

function deriveScopes(scopeParam?: string): string[] {
  const scopes = parseScopes(scopeParam);
  return scopes;
}

type ForwardedHeaderValues = {
  proto?: string;
  host?: string;
};

function firstHeaderValue(headerValue?: string | null): string | undefined {
  if (!headerValue) {
    return undefined;
  }
  const [first] = headerValue.split(',');
  const trimmed = first?.trim();
  return trimmed && trimmed.length > 0 ? trimmed : undefined;
}

function stripQuotes(value: string): string {
  if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
    return value.slice(1, -1);
  }
  return value;
}

function parseForwardedHeader(headerValue?: string | null): ForwardedHeaderValues {
  const first = firstHeaderValue(headerValue);
  if (!first) {
    return {};
  }
  const pairs = first.split(';');
  const result: ForwardedHeaderValues = {};
  for (const pair of pairs) {
    const [rawKey, rawValue] = pair.split('=');
    if (!rawValue) continue;
    const key = rawKey.trim().toLowerCase();
    const value = stripQuotes(rawValue.trim());
    if (!value) continue;
    if (key === 'proto') {
      result.proto = value;
    } else if (key === 'host') {
      result.host = value;
    }
  }
  return result;
}

function parseCfVisitorScheme(headerValue?: string | null): string | undefined {
  if (!headerValue) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(headerValue) as { scheme?: string };
    if (typeof parsed.scheme === 'string') {
      return parsed.scheme;
    }
  } catch {
    // ignore parse errors
  }
  return undefined;
}

function sanitizeScheme(value?: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  if (normalized === 'https' || normalized === 'http') {
    return normalized;
  }
  return undefined;
}

function sanitizeHost(value?: string): string | undefined {
  if (!value) {
    return undefined;
  }
  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }
  return trimmed;
}

function determineOriginalScheme(req: Request): string {
  const forwarded = parseForwardedHeader(req.get('forwarded'));
  return (
    sanitizeScheme(forwarded.proto) ??
    sanitizeScheme(parseCfVisitorScheme(req.get('cf-visitor'))) ??
    sanitizeScheme(firstHeaderValue(req.get('x-forwarded-proto'))) ??
    (req.secure || req.protocol === 'https' ? 'https' : 'http')
  );
}

function determineOriginalHost(req: Request): string {
  const forwarded = parseForwardedHeader(req.get('forwarded'));
  return (
    sanitizeHost(forwarded.host) ??
    sanitizeHost(firstHeaderValue(req.get('x-forwarded-host'))) ??
    sanitizeHost(req.get('host')) ??
    'localhost'
  );
}

function issuerFromRequest(req: Request): string {
  if (process.env.OAUTH_ISSUER) {
    return process.env.OAUTH_ISSUER;
  }
  const protocol = determineOriginalScheme(req);
  const host = determineOriginalHost(req);
  return `${protocol}://${host}`;
}

// MCP Setup -------------------------------------------------------------------

type SessionRecord = {
  transport: SSEServerTransport;
  server: McpServer;
  client: RefMDClient;
  accessToken: string;
};

const sessions = new Map<string, SessionRecord>();

function buildMcpServer(client: RefMDClient): McpServer {
  const server = new McpServer(
    {
      name: 'refmd-mcp',
      version: packageVersion,
    },
    {
      instructions:
        'Use the refmd://document/{id} resources to read Markdown content. Tools allow listing, searching, creating, and editing RefMD documents.',
    },
  );

  const documentTemplate = new ResourceTemplate('refmd://document/{id}', {
    list: async () => {
      const docs = await client.listDocuments({ state: 'active' });
      return {
        resources: docs.items.map((doc) => ({
          uri: `refmd://document/${doc.id}`,
          name: doc.title,
          description: doc.path ?? undefined,
          annotations: {
            state: doc.archived_at ? 'archived' : 'active',
            updatedAt: doc.updated_at,
          },
        })),
      };
    },
  });

  server.registerResource(
    'refmd-documents',
    documentTemplate,
    {
      title: 'RefMD Documents',
      description: 'Markdown documents stored in RefMD.',
    },
    async (uri, vars) => {
      const idValue = vars.id;
      const id =
        typeof idValue === 'string'
          ? idValue
          : Array.isArray(idValue) && typeof idValue[0] === 'string'
            ? idValue[0]
            : undefined;
      if (!id) {
        throw new Error('Document id missing in resource URI.');
      }
      const [meta, content] = await Promise.all([
        client.getDocument(id),
        client.getDocumentContent(id),
      ]);
      return {
        contents: [
          {
            uri: uri.href,
            mimeType: 'text/markdown',
            text: content,
          },
          {
            uri: `${uri.href}#metadata`,
            mimeType: 'application/json',
            text: JSON.stringify(meta, null, 2),
          },
        ],
      };
    },
  );

  server.registerTool(
    'refmd-list-documents',
    {
      title: 'List documents',
      description:
        'List recent RefMD documents. Optional filters: query, tag, state (active|archived|all).',
      inputSchema: {
        query: z.string().trim().optional(),
        tag: z.string().trim().optional(),
        state: z.enum(['active', 'archived', 'all']).optional(),
      },
    },
    async ({ query, tag, state }) => {
      const docs = await client.listDocuments({
        query: query ?? undefined,
        tag: tag ?? undefined,
        state: state ?? undefined,
      });
      return {
        content: [
          {
            type: 'text',
            text: formatDocuments(docs.items),
          },
        ],
        structuredContent: { documents: docs.items },
      };
    },
  );

  server.registerTool(
    'refmd-search-documents',
    {
      title: 'Search documents',
      description: 'Full-text search of documents by title.',
      inputSchema: {
        query: z.string().min(1, 'Provide a search query.'),
      },
    },
    async ({ query }) => {
      const results = await client.searchDocuments(query);
      return {
        content: [
          {
            type: 'text',
            text: formatSearch(results),
          },
        ],
        structuredContent: { results },
      };
    },
  );

  server.registerTool(
    'refmd-read-document',
    {
      title: 'Read document content',
      description: 'Fetch Markdown content and metadata for a document by id.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      const [meta, content] = await Promise.all([
        client.getDocument(id),
        client.getDocumentContent(id),
      ]);
      return {
        content: [
          {
            type: 'text',
            text: content || '(empty document)',
          },
        ],
        structuredContent: { document: meta, content },
      };
    },
  );

  server.registerTool(
    'refmd-update-document-content',
    {
      title: 'Update document Markdown',
      description: 'Overwrite the Markdown body of a RefMD document.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
        content: z.string(),
      },
    },
    async ({ id, content }) => {
      const updated = await client.updateDocumentContent(id, content);
      return {
        content: [
          {
            type: 'text',
            text: `Document ${updated.title} (${updated.id}) updated.`,
          },
        ],
        structuredContent: { document: updated },
      };
    },
  );

  server.registerTool(
    'refmd-create-document',
    {
      title: 'Create document',
      description:
        'Create a new RefMD document or folder. Optionally provide initial Markdown content.',
      inputSchema: {
        title: z.string().trim().optional(),
        parentId: z.string().uuid().nullable().optional(),
        type: z.enum(['document', 'folder']).optional(),
        content: z.string().optional(),
      },
    },
    async ({ title, parentId, type, content }) => {
      const created = await client.createDocument({
        title: title ?? undefined,
        parentId: parentId ?? undefined,
        type: type ?? 'document',
      });
      let finalDoc = created;
      if (content && created.type !== 'folder') {
        finalDoc = await client.updateDocumentContent(created.id, content);
      }
      return {
        content: [
          {
            type: 'text',
            text: `Created ${finalDoc.type} "${finalDoc.title}" (${finalDoc.id}).`,
          },
        ],
        structuredContent: { document: finalDoc },
      };
    },
  );

  server.registerTool(
    'refmd-update-document',
    {
      title: 'Update document metadata',
      description: 'Rename a document or change its parent folder.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
        title: z.string().trim().min(1).optional(),
        parentId: z.union([z.string().uuid(), z.null()]).optional(),
      },
    },
    async ({ id, title, parentId }) => {
      if (title === undefined && parentId === undefined) {
        return {
          content: [
            {
              type: 'text',
              text: 'Provide at least one of title or parentId.',
            },
          ],
          isError: true,
        };
      }
      const params: { id: string; title?: string; parentId?: string | null } = { id };
      if (title !== undefined) params.title = title;
      if (parentId !== undefined) params.parentId = parentId;
      const updated = await client.updateDocument(params);
      return {
        content: [
          {
            type: 'text',
            text: `Updated document "${updated.title}" (${updated.id}).`,
          },
        ],
        structuredContent: { document: updated },
      };
    },
  );

  server.registerTool(
    'refmd-archive-document',
    {
      title: 'Archive document',
      description: 'Archive a document to hide it from active views.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      const doc = await client.archiveDocument(id);
      return {
        content: [
          {
            type: 'text',
            text: `Archived document "${doc.title}" (${doc.id}).`,
          },
        ],
        structuredContent: { document: doc },
      };
    },
  );

  server.registerTool(
    'refmd-unarchive-document',
    {
      title: 'Unarchive document',
      description: 'Restore a previously archived document.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      const doc = await client.unarchiveDocument(id);
      return {
        content: [
          {
            type: 'text',
            text: `Unarchived document "${doc.title}" (${doc.id}).`,
          },
        ],
        structuredContent: { document: doc },
      };
    },
  );

  server.registerTool(
    'refmd-delete-document',
    {
      title: 'Delete document',
      description: 'Permanently delete a document. Requires appropriate permissions.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      await client.deleteDocument(id);
      return {
        content: [
          {
            type: 'text',
            text: `Deleted document ${id}.`,
          },
        ],
      };
    },
  );

  server.registerTool(
    'refmd-list-backlinks',
    {
      title: 'List backlinks',
      description: 'List documents that link to the specified document.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      const backlinks = await client.listBacklinks(id);
      return {
        content: [
          {
            type: 'text',
            text: formatBacklinksList(backlinks),
          },
        ],
        structuredContent: { backlinks },
      };
    },
  );

  server.registerTool(
    'refmd-list-outgoing-links',
    {
      title: 'List outgoing links',
      description: 'List documents referenced by the specified document.',
      inputSchema: {
        id: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ id }) => {
      const links = await client.listOutgoingLinks(id);
      return {
        content: [
          {
            type: 'text',
            text: formatOutgoingLinksList(links),
          },
        ],
        structuredContent: { links },
      };
    },
  );

  server.registerTool(
    'refmd-list-snapshots',
    {
      title: 'List document snapshots',
      description: 'Show snapshot history for a document.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
        limit: z.number().int().min(1).max(200).optional(),
        offset: z.number().int().min(0).optional(),
      },
    },
    async ({ documentId, limit, offset }) => {
      const response = await client.listSnapshots(documentId, {
        limit: limit ?? undefined,
        offset: offset ?? undefined,
      });
      return {
        content: [
          {
            type: 'text',
            text: formatSnapshotsList(response.items),
          },
        ],
        structuredContent: { snapshots: response.items },
      };
    },
  );

  server.registerTool(
    'refmd-get-snapshot-diff',
    {
      title: 'Get snapshot diff',
      description: 'Compare a document snapshot against the current state or another snapshot.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
        snapshotId: z.string().uuid('Provide a snapshot id.'),
        compareSnapshotId: z.string().uuid().optional(),
        base: z.enum(['auto', 'current', 'previous']).optional(),
      },
    },
    async ({ documentId, snapshotId, compareSnapshotId, base }) => {
      const diff = await client.getSnapshotDiff({
        documentId,
        snapshotId,
        compareSnapshotId: compareSnapshotId ?? undefined,
        base: base ?? undefined,
      });
      const summary = `Diff ready: base=${diff.base.kind}, target=${diff.target.kind}.`;
      return {
        content: [
          {
            type: 'text',
            text: summary,
          },
        ],
        structuredContent: { diff },
      };
    },
  );

  server.registerTool(
    'refmd-restore-snapshot',
    {
      title: 'Restore snapshot',
      description: 'Restore a document from a snapshot.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
        snapshotId: z.string().uuid('Provide a snapshot id.'),
      },
    },
    async ({ documentId, snapshotId }) => {
      const restored = await client.restoreSnapshot({ documentId, snapshotId });
      return {
        content: [
          {
            type: 'text',
            text: `Restored snapshot ${restored.snapshot.id} for document ${documentId}.`,
          },
        ],
        structuredContent: { snapshot: restored.snapshot },
      };
    },
  );

  server.registerTool(
    'refmd-create-share',
    {
      title: 'Create share link',
      description: 'Create a public share link for a document or folder.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
        permission: z.string().trim().optional(),
        expiresAt: z.string().trim().optional(),
      },
    },
    async ({ documentId, permission, expiresAt }) => {
      const share = await client.createShare({
        documentId,
        permission: permission ?? undefined,
        expires_at: expiresAt ?? undefined,
      });
      return {
        content: [
          {
            type: 'text',
            text: `Created share link: ${share.url}`,
          },
        ],
        structuredContent: { share },
      };
    },
  );

  server.registerTool(
    'refmd-list-document-shares',
    {
      title: 'List share links for document',
      description: 'List existing share links for a document.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ documentId }) => {
      const shares = await client.listDocumentShares(documentId);
      return {
        content: [
          {
            type: 'text',
            text: formatSharesList(shares),
          },
        ],
        structuredContent: { shares },
      };
    },
  );

  server.registerTool(
    'refmd-delete-share',
    {
      title: 'Delete share link',
      description: 'Revoke an existing share link by token.',
      inputSchema: {
        token: z.string().trim().min(1, 'Provide a share token.'),
      },
    },
    async ({ token }) => {
      await client.deleteShare(token);
      return {
        content: [
          {
            type: 'text',
            text: `Deleted share token ${token}.`,
          },
        ],
      };
    },
  );

  server.registerTool(
    'refmd-list-applicable-shares',
    {
      title: 'List applicable share links',
      description: 'List share links that affect a specific document.',
      inputSchema: {
        documentId: z.string().uuid('Provide a valid document id.'),
      },
    },
    async ({ documentId }) => {
      const shares = await client.listApplicableShares(documentId);
      return {
        content: [
          {
            type: 'text',
            text: formatApplicableShares(shares),
          },
        ],
        structuredContent: { shares },
      };
    },
  );

  server.registerTool(
    'refmd-list-tags',
    {
      title: 'List tags',
      description: 'List tags visible to the current user.',
      inputSchema: {
        query: z.string().trim().optional(),
      },
    },
    async ({ query }) => {
      const tags = await client.listTags({ query: query ?? undefined });
      return {
        content: [
          {
            type: 'text',
            text: formatTags(tags),
          },
        ],
        structuredContent: { tags },
      };
    },
  );

  return server;
}

// OAuth Routes ---------------------------------------------------------------

const authorizeQuerySchema = z.object({
  response_type: z.literal('code'),
  client_id: z.string().min(1),
  redirect_uri: z.string().url(),
  state: z.string().optional(),
  scope: z.string().optional(),
  code_challenge: z.string().min(1),
  code_challenge_method: z.string().optional(),
});

const authorizeFormSchema = authorizeQuerySchema.extend({
  token: z.string().min(1, 'Provide a RefMD API token'),
});

const tokenRequestSchema = z.object({
  grant_type: z.enum(['authorization_code', 'refresh_token']),
  code: z.string().optional(),
  redirect_uri: z.string().optional(),
  client_id: z.string().optional(),
  code_verifier: z.string().optional(),
  refresh_token: z.string().optional(),
});

const redirectUriArraySchema = z.preprocess((value) => {
  if (typeof value === 'string') {
    return [value];
  }
  return value;
}, z.array(z.string().url()).min(1));

const stringArraySchema = z.preprocess((value) => {
  if (typeof value === 'string') {
    return [value];
  }
  return value;
}, z.array(z.string().min(1)));

const clientRegistrationSchema = z
  .object({
    client_name: z.string().trim().optional(),
    redirect_uris: redirectUriArraySchema,
    grant_types: stringArraySchema.optional(),
    response_types: stringArraySchema.optional(),
    token_endpoint_auth_method: z.string().trim().optional(),
    scope: z.string().trim().optional(),
  })
  .passthrough();

type AuthorizationRequestValues = Omit<
  z.infer<typeof authorizeQuerySchema>,
  'code_challenge_method'
> & {
  code_challenge_method: 'S256' | 'plain';
};

type AuthorizationFormValues = AuthorizationRequestValues & {
  token: string;
};

function normalizeCodeChallengeMethod(method?: string | null): 'S256' | 'plain' {
  if (!method) {
    return 'S256';
  }
  const trimmed = method.trim();
  if (!trimmed) {
    return 'S256';
  }
  const upper = trimmed.toUpperCase();
  if (upper === 'S256') {
    return 'S256';
  }
  if (upper === 'PLAIN') {
    return 'plain';
  }
  throw new Error('Unsupported code_challenge_method');
}

function ensureAuthorizationRequestValues(
  input: z.infer<typeof authorizeQuerySchema>,
): AuthorizationRequestValues {
  return {
    ...input,
    code_challenge_method: normalizeCodeChallengeMethod(input.code_challenge_method),
  };
}

function ensureAuthorizationFormValues(
  input: z.infer<typeof authorizeFormSchema>,
): AuthorizationFormValues {
  const base = ensureAuthorizationRequestValues(input);
  return {
    ...base,
    token: input.token,
  };
}

function buildFallbackAuthorizationValues(raw: {
  client_id?: string;
  redirect_uri?: string;
  state?: string;
  scope?: string;
  code_challenge?: string;
  code_challenge_method?: string;
}): AuthorizationRequestValues {
  let method: 'S256' | 'plain';
  try {
    method = normalizeCodeChallengeMethod(raw.code_challenge_method);
  } catch {
    method = 'S256';
  }
  return {
    response_type: 'code',
    client_id: raw.client_id ?? '',
    redirect_uri: raw.redirect_uri ?? '',
    state: raw.state,
    scope: raw.scope,
    code_challenge: raw.code_challenge ?? '',
    code_challenge_method: method,
  };
}

const HTML_ESCAPE_LOOKUP: Record<string, string> = {
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
};

function escapeHtml(value: string): string {
  return value.replace(/[&<>"']/g, (char) => HTML_ESCAPE_LOOKUP[char] ?? char);
}

function renderAuthorizePage(params: {
  values: AuthorizationRequestValues;
  error?: string;
}): string {
  const { values, error } = params;
  const hiddenInputs = Object.entries(values)
    .filter(([, value]) => value !== undefined)
    .map(([key, value]) => {
      const stringValue = typeof value === 'string' ? value : String(value);
      return `<input type="hidden" name="${escapeHtml(key)}" value="${escapeHtml(stringValue)}" />`;
    })
    .join('\n');
  const errorMarkup = error
    ? `<div class="error">${escapeHtml(error)}</div>`
    : '';
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1" />
    <title>Authorize RefMD MCP</title>
    <style>
      body { font-family: system-ui, sans-serif; background: #0f1729; color: #f1f5f9; display: flex; justify-content: center; padding: 40px; }
      main { background: rgba(15, 23, 42, 0.85); border: 1px solid rgba(148, 163, 184, 0.3); border-radius: 12px; padding: 32px; width: min(480px, 100%); box-shadow: 0 20px 40px rgba(15, 23, 42, 0.45); }
      h1 { font-size: 1.4rem; margin-bottom: 0.5rem; }
      p { color: #cbd5f5; font-size: 0.95rem; line-height: 1.4; }
      label { display: block; font-size: 0.85rem; margin-bottom: 0.35rem; color: #e2e8f0; }
      input[type="password"], input[type="text"] { width: 100%; padding: 0.65rem 0.75rem; border-radius: 8px; border: 1px solid rgba(148, 163, 184, 0.4); background: rgba(15, 23, 42, 0.6); color: #f8fafc; font-size: 0.95rem; box-sizing: border-box; }
      input[type="password"]:focus { outline: 2px solid #60a5fa; }
      button { appearance: none; border: none; background: linear-gradient(135deg, #38bdf8, #818cf8); color: #0f1729; font-weight: 600; padding: 0.65rem 1rem; border-radius: 8px; cursor: pointer; width: 100%; margin-top: 1rem; font-size: 0.95rem; box-sizing: border-box; }
      button:disabled { opacity: 0.6; cursor: not-allowed; }
      .error { background: rgba(248, 113, 113, 0.12); border: 1px solid rgba(248, 113, 113, 0.35); color: #fecaca; padding: 0.75rem; border-radius: 8px; margin-bottom: 1rem; }
      .input-group { margin-top: 1.25rem; }
      .meta { font-size: 0.8rem; color: #94a3b8; margin-top: 0.75rem; }
    </style>
  </head>
  <body>
    <main>
      <h1>Authorize RefMD MCP</h1>
      <p>Enter a RefMD API token with access to your documents. The token will be securely stored for this connector and can be revoked from your profile at any time.</p>
      ${errorMarkup}
      <form method="post" action="/oauth/authorize">
        ${hiddenInputs}
        <div class="input-group">
          <label for="token">RefMD API token</label>
          <input id="token" name="token" type="password" autocomplete="off" required />
        </div>
        <button type="submit">Authorize</button>
      </form>
      <p class="meta">Client: <strong>${escapeHtml(values.client_id)}</strong></p>
      <p class="meta">Redirect URI: <strong>${escapeHtml(values.redirect_uri)}</strong></p>
    </main>
  </body>
</html>`;
}

// Routes ----------------------------------------------------------------------

const oauthMetadataPaths = [
  '/.well-known/oauth-authorization-server',
  '/.well-known/oauth-authorization-server/mcp',
  '/mcp/.well-known/oauth-authorization-server',
];

const oauthProtectedResourcePaths = [
  '/.well-known/oauth-protected-resource',
  '/.well-known/oauth-protected-resource/*',
  '/mcp/.well-known/oauth-protected-resource',
  '/mcp/.well-known/oauth-protected-resource/*',
];

app.post('/register', (req: Request, res: ExpressResponse) => {
  const parsed = clientRegistrationSchema.safeParse(req.body ?? {});
  if (!parsed.success) {
    logRegisterError(req, 'invalid_client_metadata (schema)', parsed.error.flatten());
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'Invalid client registration payload.',
      details: parsed.error.flatten(),
    });
    return;
  }

  const payload = parsed.data;
  const redirectUris = payload.redirect_uris;
  const requestedGrantTypes = payload.grant_types ?? ['authorization_code', 'refresh_token'];
  const unsupportedGrantType = requestedGrantTypes.find(
    (value) => value !== 'authorization_code' && value !== 'refresh_token',
  );
  if (unsupportedGrantType) {
    logRegisterError(req, `unsupported grant_type: ${unsupportedGrantType}`, payload);
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: `Unsupported grant_type: ${unsupportedGrantType}`,
    });
    return;
  }
  if (!requestedGrantTypes.includes('authorization_code')) {
    logRegisterError(req, 'authorization_code grant_type missing', payload);
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'authorization_code grant_type is required',
    });
    return;
  }
  const grantTypes = Array.from(
    new Set(requestedGrantTypes.filter((value) => value === 'authorization_code' || value === 'refresh_token')),
  );

  const requestedResponseTypes = payload.response_types ?? ['code'];
  const unsupportedResponseType = requestedResponseTypes.find((value) => value !== 'code');
  if (unsupportedResponseType) {
    logRegisterError(req, `unsupported response_type: ${unsupportedResponseType}`, payload);
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: `Unsupported response_type: ${unsupportedResponseType}`,
    });
    return;
  }
  const responseTypes = ['code'];

  const tokenEndpointAuthMethod = (payload.token_endpoint_auth_method ?? 'none').toLowerCase();
  if (tokenEndpointAuthMethod !== 'none') {
    logRegisterError(
      req,
      `unsupported token_endpoint_auth_method: ${tokenEndpointAuthMethod}`,
      payload,
    );
    res.status(400).json({
      error: 'invalid_client_metadata',
      error_description: 'Only public clients (token_endpoint_auth_method "none") are supported',
    });
    return;
  }

  for (const uri of redirectUris) {
    if (!isRedirectUriSafe(uri)) {
      logRegisterError(req, `invalid_redirect_uri: ${uri}`, payload);
      res.status(400).json({
        error: 'invalid_redirect_uri',
        error_description: `Redirect URI not allowed: ${uri}`,
      });
      return;
    }
  }

  const clientId = randomToken(24);
  rememberClientRegistration(clientId, redirectUris);
  logInfo(req, 'client registered', {
    clientId,
    redirectUris,
    grantTypes,
    responseTypes,
  });

  res.status(201).json({
    client_id: clientId,
    client_id_issued_at: Math.floor(Date.now() / 1000),
    client_name: payload.client_name,
    redirect_uris: redirectUris,
    grant_types: grantTypes,
    response_types: responseTypes,
    token_endpoint_auth_method: 'none',
    scope: payload.scope,
  });
});

app.get(oauthMetadataPaths, (req: Request, res: ExpressResponse) => {
  const issuer = issuerFromRequest(req);
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    registration_endpoint: `${issuer}/register`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: SUPPORTED_SCOPES,
  });
});

app.get(oauthProtectedResourcePaths, (req: Request, res: ExpressResponse) => {
  const resourcePath = resolveResourcePathFromMetadataRequest(req.path);
  const info = buildResourceMetadataInfo(req, resourcePath);
  res.json({
    resource: info.resource,
    resource_name: 'RefMD MCP',
    authorization_servers: [info.issuer],
    scopes_supported: SUPPORTED_SCOPES,
    bearer_methods_supported: ['authorization_header'],
  });
});

const openidConfigurationPaths = [
  '/.well-known/openid-configuration',
  '/.well-known/openid-configuration/mcp',
  '/mcp/.well-known/openid-configuration',
];

app.get(openidConfigurationPaths, (req: Request, res: ExpressResponse) => {
  const issuer = issuerFromRequest(req);
  res.json({
    issuer,
    authorization_endpoint: `${issuer}/oauth/authorize`,
    token_endpoint: `${issuer}/oauth/token`,
    revocation_endpoint: `${issuer}/oauth/revoke`,
    response_types_supported: ['code'],
    grant_types_supported: ['authorization_code', 'refresh_token'],
    code_challenge_methods_supported: ['S256', 'plain'],
    token_endpoint_auth_methods_supported: ['none'],
    scopes_supported: SUPPORTED_SCOPES,
  });
});

app.get('/oauth/authorize', (req: Request, res: ExpressResponse) => {
  const parsed = authorizeQuerySchema.safeParse({
    response_type: firstString(req.query.response_type),
    client_id: firstString(req.query.client_id),
    redirect_uri: firstString(req.query.redirect_uri),
    state: firstString(req.query.state),
    scope: firstString(req.query.scope),
    code_challenge: firstString(req.query.code_challenge),
    code_challenge_method: firstString(req.query.code_challenge_method),
  });

  if (!parsed.success) {
    logWarn(req, 'authorize query validation failed', { issues: parsed.error.flatten() });
    res.status(400).send('Invalid authorization request');
    return;
  }

  let values: AuthorizationRequestValues;
  try {
    values = ensureAuthorizationRequestValues(parsed.data);
  } catch {
    logWarn(req, 'authorize query had unsupported code_challenge_method');
    res.status(400).send('Unsupported code_challenge_method');
    return;
  }

  const validation = validateClientAndRedirect(values.client_id, values.redirect_uri);
  if (!validation.ok) {
    logWarn(req, 'authorize client validation failed', {
      clientId: values.client_id,
      redirectUri: values.redirect_uri,
      error: validation.error,
    });
    res.status(400).send(validation.error ?? 'invalid_client');
    return;
  }

  logInfo(req, 'authorize consent page rendered', {
    clientId: values.client_id,
    redirectUri: values.redirect_uri,
    scope: values.scope,
  });

  res
    .status(200)
    .send(
      renderAuthorizePage({
        values,
      }),
    );
});

app.post('/oauth/authorize', async (req: Request, res: ExpressResponse) => {
  const parsed = authorizeFormSchema.safeParse({
    response_type: req.body?.response_type,
    client_id: req.body?.client_id,
    redirect_uri: req.body?.redirect_uri,
    state: req.body?.state,
    scope: req.body?.scope,
    code_challenge: req.body?.code_challenge,
    code_challenge_method: req.body?.code_challenge_method,
    token: req.body?.token,
  });

  if (!parsed.success) {
    logWarn(req, 'authorize form validation failed', {
      clientId: req.body?.client_id,
      redirectUri: req.body?.redirect_uri,
      issues: parsed.error.flatten(),
    });
    const fallback = authorizeQuerySchema.safeParse({
      response_type: req.body?.response_type,
      client_id: req.body?.client_id,
      redirect_uri: req.body?.redirect_uri,
      state: req.body?.state,
      scope: req.body?.scope,
      code_challenge: req.body?.code_challenge,
      code_challenge_method: req.body?.code_challenge_method,
    });
    const values =
      fallback.success
        ? (() => {
            try {
              return ensureAuthorizationRequestValues(fallback.data);
            } catch {
              return buildFallbackAuthorizationValues({
                client_id: fallback.data.client_id,
                redirect_uri: fallback.data.redirect_uri,
                state: fallback.data.state,
                scope: fallback.data.scope,
                code_challenge: fallback.data.code_challenge,
                code_challenge_method: fallback.data.code_challenge_method,
              });
            }
          })()
        : buildFallbackAuthorizationValues({
            client_id: req.body?.client_id,
            redirect_uri: req.body?.redirect_uri,
            state: req.body?.state,
            scope: req.body?.scope,
            code_challenge: req.body?.code_challenge,
            code_challenge_method: req.body?.code_challenge_method,
          });
    res.status(400).send(renderAuthorizePage({ values, error: 'Invalid submission' }));
    return;
  }

  let values: AuthorizationFormValues;
  try {
    values = ensureAuthorizationFormValues(parsed.data);
  } catch {
    logWarn(req, 'authorize form had unsupported code_challenge_method', {
      clientId: parsed.data.client_id,
      redirectUri: parsed.data.redirect_uri,
    });
    res
      .status(400)
      .send(
        renderAuthorizePage({
          values: buildFallbackAuthorizationValues({
            client_id: parsed.data.client_id,
            redirect_uri: parsed.data.redirect_uri,
            state: parsed.data.state,
            scope: parsed.data.scope,
            code_challenge: parsed.data.code_challenge,
            code_challenge_method: parsed.data.code_challenge_method,
          }),
          error: 'Unsupported code_challenge_method',
        }),
      );
    return;
  }

  const validation = validateClientAndRedirect(values.client_id, values.redirect_uri);
  if (!validation.ok) {
    logWarn(req, 'authorize form client validation failed', {
      clientId: values.client_id,
      redirectUri: values.redirect_uri,
      error: validation.error,
    });
    res
      .status(400)
      .send(
        renderAuthorizePage({
          values,
          error: validation.error ?? 'Client not allowed',
        }),
      );
    return;
  }

  try {
    const user = await fetchCurrentUser(BASE_URL, values.token);
    const code = randomToken(48);
    const scope = deriveScopes(values.scope);
    await storeAuthorizationCode(code, {
      clientId: values.client_id,
      redirectUri: values.redirect_uri,
      codeChallenge: values.code_challenge,
      codeChallengeMethod: values.code_challenge_method,
      refmdToken: values.token,
      user,
      scope,
      expiresAt: Date.now() + AUTH_CODE_TTL_MS,
    });

    const redirect = new URL(values.redirect_uri);
    redirect.searchParams.set('code', code);
    if (values.state) {
      redirect.searchParams.set('state', values.state);
    }
    logInfo(req, 'issued authorization code', {
      clientId: values.client_id,
      userId: user.id,
      scope,
    });
    res.redirect(redirect.toString());
  } catch (error) {
    logError(req, 'RefMD token validation failed', {
      clientId: values.client_id,
      redirectUri: values.redirect_uri,
      error: error instanceof Error ? error.message : String(error),
    });
    res
      .status(401)
      .send(
        renderAuthorizePage({
          values,
          error: 'Failed to verify RefMD token. Please try again.',
        }),
      );
    return;
  }
});

app.post('/oauth/token', async (req: Request, res: ExpressResponse) => {
  const parsed = tokenRequestSchema.safeParse({
    grant_type: req.body?.grant_type,
    code: req.body?.code,
    redirect_uri: req.body?.redirect_uri,
    client_id: req.body?.client_id,
    code_verifier: req.body?.code_verifier,
    refresh_token: req.body?.refresh_token,
  });

  if (!parsed.success) {
    logWarn(req, 'token request validation failed', { issues: parsed.error.flatten() });
    res.status(400).json({ error: 'invalid_request' });
    return;
  }

  const body = parsed.data;
  if (body.grant_type === 'authorization_code') {
    if (!body.code || !body.code_verifier || !body.redirect_uri || !body.client_id) {
      logWarn(req, 'token request missing authorization_code parameters', {
        clientId: body.client_id,
        redirectUri: body.redirect_uri,
      });
      res.status(400).json({ error: 'invalid_request' });
      return;
    }

    const record = await consumeAuthorizationCode(body.code);
    if (!record) {
      logWarn(req, 'authorization_code not found or expired', {
        clientId: body.client_id,
        code: maskSecret(body.code),
      });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    if (record.clientId !== body.client_id || record.redirectUri !== body.redirect_uri) {
      logWarn(req, 'authorization_code client mismatch', {
        requestClient: body.client_id,
        recordClient: record.clientId,
      });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    if (record.codeChallengeMethod === 'S256') {
      const computed = hashCodeVerifier(body.code_verifier);
      if (computed !== record.codeChallenge) {
        logWarn(req, 'code_verifier mismatch (S256)', { clientId: body.client_id });
        res.status(400).json({ error: 'invalid_grant' });
        return;
      }
    } else if (record.codeChallengeMethod === 'plain') {
      if (body.code_verifier !== record.codeChallenge) {
        logWarn(req, 'code_verifier mismatch (plain)', { clientId: body.client_id });
        res.status(400).json({ error: 'invalid_grant' });
        return;
      }
    } else {
      logWarn(req, 'authorization_code had unsupported codeChallengeMethod', {
        method: record.codeChallengeMethod,
      });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }

    const { access, refreshToken } = await issueTokens({
      clientId: record.clientId,
      refmdToken: record.refmdToken,
      user: record.user,
      scope: record.scope,
      generateRefresh: true,
    });

    logInfo(req, 'issued tokens via authorization_code', {
      clientId: record.clientId,
      userId: record.user.id,
      scope: record.scope,
    });
    res
      .status(200)
      .set('Cache-Control', 'no-store')
      .set('Pragma', 'no-cache')
      .json({
        token_type: 'Bearer',
        access_token: access.accessToken,
        expires_in: Math.floor((access.expiresAt - Date.now()) / 1000),
        refresh_token: refreshToken?.refreshToken,
        scope: record.scope.join(' '),
      });
    return;
  }

  if (body.grant_type === 'refresh_token') {
    if (!body.refresh_token || !body.client_id) {
      logWarn(req, 'token request missing refresh_token parameters', {
        clientId: body.client_id,
      });
      res.status(400).json({ error: 'invalid_request' });
      return;
    }
    const record = await getRefreshTokenRecord(body.refresh_token);
    if (!record || record.clientId !== body.client_id) {
      logWarn(req, 'refresh_token invalid or client mismatch', {
        clientId: body.client_id,
      });
      res.status(400).json({ error: 'invalid_grant' });
      return;
    }
    await pruneAccessTokensByRefresh(body.refresh_token);
    await tokenStore.deleteRefreshToken(body.refresh_token);

    const { access, refreshToken } = await issueTokens({
      clientId: record.clientId,
      refmdToken: record.refmdToken,
      user: record.user,
      scope: record.scope,
      generateRefresh: true,
    });

    logInfo(req, 'issued tokens via refresh_token', {
      clientId: record.clientId,
      userId: record.user.id,
      scope: record.scope,
    });
    res
      .status(200)
      .set('Cache-Control', 'no-store')
      .set('Pragma', 'no-cache')
      .json({
        token_type: 'Bearer',
        access_token: access.accessToken,
        expires_in: Math.floor((access.expiresAt - Date.now()) / 1000),
        refresh_token: refreshToken?.refreshToken,
        scope: record.scope.join(' '),
      });
    return;
  }

  logWarn(req, 'unsupported grant_type', { grantType: body.grant_type });
  res.status(400).json({ error: 'unsupported_grant_type' });
});

app.post('/oauth/revoke', async (req: Request, res: ExpressResponse) => {
  const token = firstString(req.body?.token);
  if (!token) {
    logWarn(req, 'revoke request missing token');
    res.status(400).json({ error: 'invalid_request' });
    return;
  }
  const accessRecord = await getAccessTokenRecord(token);
  if (accessRecord) {
    await tokenStore.deleteAccessToken(token);
    if (accessRecord.refreshToken) {
      await pruneAccessTokensByRefresh(accessRecord.refreshToken);
      await tokenStore.deleteRefreshToken(accessRecord.refreshToken);
    }
  }
  const refreshRecord = await getRefreshTokenRecord(token);
  if (refreshRecord) {
    await pruneAccessTokensByRefresh(token);
    await tokenStore.deleteRefreshToken(token);
  }
  logInfo(req, 'token revoked', {
    tokenHint: maskSecret(token),
    revokedAccess: Boolean(accessRecord),
    revokedRefresh: Boolean(refreshRecord),
  });
  res.status(200).send();
});

app.get('/sse', async (req: Request, res: ExpressResponse) => {
  try {
    const bearer = extractBearerToken(req);
    if (!bearer) {
      sendUnauthorized(req, res);
      return;
    }
    const tokenRecord = await getAccessTokenRecord(bearer);
    if (!tokenRecord) {
      sendUnauthorized(req, res);
      return;
    }

    const client = new RefMDClient({ baseUrl: BASE_URL, token: tokenRecord.refmdToken });
    const server = buildMcpServer(client);
    const transport = new SSEServerTransport('/sse/messages', res);

    const sessionId = transport.sessionId;
    sessions.set(sessionId, { transport, server, client, accessToken: bearer });
    logInfo(req, 'SSE session established', {
      sessionId,
      clientId: tokenRecord.clientId,
      userId: tokenRecord.user.id,
    });

    res.on('close', () => {
      sessions.delete(sessionId);
      transport.close().catch(() => {});
      server.close().catch(() => {});
    });

    await server.connect(transport);
  } catch (error) {
    logError(req, 'Failed to establish SSE connection', {
      error: error instanceof Error ? error.message : String(error),
    });
    if (!res.headersSent) {
      res.status(500).send('Failed to establish SSE connection');
    } else {
      res.end();
    }
  }
});

app.post('/sse/messages', async (req: Request, res: ExpressResponse) => {
  const rawSession = req.query.sessionId;
  const sessionId =
    typeof rawSession === 'string'
      ? rawSession
      : Array.isArray(rawSession) && typeof rawSession[0] === 'string'
        ? rawSession[0]
        : undefined;
  if (!sessionId) {
    logWarn(req, 'SSE message missing sessionId');
    res.status(400).send('Missing sessionId query parameter.');
    return;
  }

  const session = sessions.get(sessionId);
  if (!session) {
    logWarn(req, 'SSE session not found', { sessionId });
    res.status(404).send('Unknown session.');
    return;
  }

  const tokenRecord = await getAccessTokenRecord(session.accessToken);
  if (!tokenRecord) {
    sessions.delete(sessionId);
    sendUnauthorized(req, res);
    session.transport.close().catch(() => {});
    session.server.close().catch(() => {});
    return;
  }

  try {
    await session.transport.handlePostMessage(req, res, req.body);
  } catch (error) {
    logError(req, 'Failed to handle SSE POST message', {
      sessionId,
      error: error instanceof Error ? error.message : String(error),
    });
    if (!res.headersSent) {
      res.status(500).send('Failed to handle message');
    }
  }
});

app.post('/mcp', async (req: Request, res: ExpressResponse) => {
  const bearer = extractBearerToken(req);
  if (!bearer) {
    sendUnauthorized(req, res);
    return;
  }
  const tokenRecord = await getAccessTokenRecord(bearer);
  if (!tokenRecord) {
    sendUnauthorized(req, res);
    return;
  }

  const client = new RefMDClient({ baseUrl: BASE_URL, token: tokenRecord.refmdToken });
  const server = buildMcpServer(client);
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
    enableJsonResponse: true,
  });

  normalizeAcceptHeaderForStreamableTransport(req);

  res.on('close', () => {
    void transport.close();
    void server.close();
  });

  try {
    await server.connect(transport);
    logInfo(req, 'Streamable MCP request handled', {
      clientId: tokenRecord.clientId,
      userId: tokenRecord.user.id,
    });
    await transport.handleRequest(req, res, req.body);
  } catch (error) {
    logError(req, 'Failed to handle /mcp request', {
      error: error instanceof Error ? error.message : String(error),
    });
    if (!res.headersSent) {
      res.status(500).send('Failed to process MCP request');
    }
    void transport.close();
    void server.close();
  }
});

const port = Number.parseInt(process.env.PORT ?? '3334', 10);
const host = process.env.HOST ?? '0.0.0.0';

app.listen(port, host, () => {
  console.log(`RefMD MCP server listening on http://${host}:${port}/sse`);
});

process.on('SIGINT', () => {
  console.log('Shutting down server...');
  for (const [, session] of sessions) {
    session.transport.close().catch(() => {});
    session.server.close().catch(() => {});
  }
  tokenStore.close().catch((error) => {
    console.error('Failed to close token store cleanly:', error);
  });
  process.exit(0);
});
function logRegisterError(req: Request, reason: string, payload?: unknown): void {
  const fields = payload ? { payload } : undefined;
  logWarn(req, `register failed: ${reason}`, fields);
}

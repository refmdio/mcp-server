import { promises as fs } from 'node:fs';
import path from 'node:path';
import { Kysely, MysqlDialect, PostgresDialect, SqliteDialect } from 'kysely';
import {
  RefMDUser,
  StoredAccessToken,
  StoredAuthorizationCode,
  StoredRefreshToken,
} from './types.js';

type TokenStoreDriver = 'sqlite' | 'postgres' | 'mysql';

type TokenStoreConfig =
  | {
      driver: TokenStoreDriver;
      url?: string;
      sqlitePath?: string;
    }
  | undefined;

type AuthorizationCodeRow = {
  code: string;
  client_id: string;
  redirect_uri: string;
  code_challenge: string;
  code_challenge_method: 'S256' | 'plain';
  refmd_token: string;
  user_id: string;
  user_email: string;
  user_name: string;
  scope: string;
  expires_at: number;
  created_at: number;
};

type AccessTokenRow = {
  access_token: string;
  client_id: string;
  refmd_token: string;
  user_id: string;
  user_email: string;
  user_name: string;
  scope: string;
  expires_at: number;
  refresh_token: string | null;
  created_at: number;
};

type RefreshTokenRow = {
  refresh_token: string;
  client_id: string;
  refmd_token: string;
  user_id: string;
  user_email: string;
  user_name: string;
  scope: string;
  expires_at: number;
  created_at: number;
};

interface TokenDatabase {
  authorization_codes: AuthorizationCodeRow;
  access_tokens: AccessTokenRow;
  refresh_tokens: RefreshTokenRow;
}

export interface TokenStore {
  saveAuthorizationCode(code: string, record: StoredAuthorizationCode): Promise<void>;
  consumeAuthorizationCode(code: string): Promise<StoredAuthorizationCode | null>;
  saveAccessToken(record: StoredAccessToken): Promise<void>;
  getAccessToken(token: string): Promise<StoredAccessToken | null>;
  deleteAccessToken(token: string): Promise<void>;
  saveRefreshToken(record: StoredRefreshToken): Promise<void>;
  getRefreshToken(token: string): Promise<StoredRefreshToken | null>;
  deleteRefreshToken(token: string): Promise<void>;
  deleteAccessTokensByRefreshToken(refreshToken: string): Promise<void>;
  close(): Promise<void>;
}

class InMemoryTokenStore implements TokenStore {
  private authorizationCodes = new Map<string, StoredAuthorizationCode>();
  private accessTokens = new Map<string, StoredAccessToken>();
  private refreshTokens = new Map<string, StoredRefreshToken>();

  async saveAuthorizationCode(code: string, record: StoredAuthorizationCode): Promise<void> {
    this.authorizationCodes.set(code, record);
  }

  async consumeAuthorizationCode(code: string): Promise<StoredAuthorizationCode | null> {
    const record = this.authorizationCodes.get(code);
    if (!record) return null;
    if (record.expiresAt <= Date.now()) {
      this.authorizationCodes.delete(code);
      return null;
    }
    this.authorizationCodes.delete(code);
    return record;
  }

  async saveAccessToken(record: StoredAccessToken): Promise<void> {
    this.accessTokens.set(record.accessToken, record);
  }

  async getAccessToken(token: string): Promise<StoredAccessToken | null> {
    const record = this.accessTokens.get(token);
    return record ?? null;
  }

  async deleteAccessToken(token: string): Promise<void> {
    this.accessTokens.delete(token);
  }

  async saveRefreshToken(record: StoredRefreshToken): Promise<void> {
    this.refreshTokens.set(record.refreshToken, record);
  }

  async getRefreshToken(token: string): Promise<StoredRefreshToken | null> {
    const record = this.refreshTokens.get(token);
    return record ?? null;
  }

  async deleteRefreshToken(token: string): Promise<void> {
    this.refreshTokens.delete(token);
  }

  async deleteAccessTokensByRefreshToken(refreshToken: string): Promise<void> {
    for (const [token, record] of this.accessTokens.entries()) {
      if (record.refreshToken === refreshToken) {
        this.accessTokens.delete(token);
      }
    }
  }

  async close(): Promise<void> {
    this.authorizationCodes.clear();
    this.accessTokens.clear();
    this.refreshTokens.clear();
  }
}

class KyselyTokenStore implements TokenStore {
  constructor(
    private readonly db: Kysely<TokenDatabase>,
    private readonly destroyFn: () => Promise<void> | void,
  ) {}

  async saveAuthorizationCode(code: string, record: StoredAuthorizationCode): Promise<void> {
    await this.db
      .deleteFrom('authorization_codes')
      .where('code', '=', code)
      .execute();
    await this.db
      .insertInto('authorization_codes')
      .values({
        code,
        client_id: record.clientId,
        redirect_uri: record.redirectUri,
        code_challenge: record.codeChallenge,
        code_challenge_method: record.codeChallengeMethod,
        refmd_token: record.refmdToken,
        user_id: record.user.id,
        user_email: record.user.email,
        user_name: record.user.name,
        scope: JSON.stringify(record.scope),
        expires_at: record.expiresAt,
        created_at: Date.now(),
      })
      .execute();
  }

  async consumeAuthorizationCode(code: string): Promise<StoredAuthorizationCode | null> {
    const row = await this.db
      .selectFrom('authorization_codes')
      .selectAll()
      .where('code', '=', code)
      .executeTakeFirst();
    if (!row) return null;
    await this.db.deleteFrom('authorization_codes').where('code', '=', code).execute();
    if (row.expires_at <= Date.now()) {
      return null;
    }
    return {
      clientId: row.client_id,
      redirectUri: row.redirect_uri,
      codeChallenge: row.code_challenge,
      codeChallengeMethod: row.code_challenge_method,
      refmdToken: row.refmd_token,
      user: createUser(row),
      scope: JSON.parse(row.scope) as string[],
      expiresAt: row.expires_at,
    };
  }

  async saveAccessToken(record: StoredAccessToken): Promise<void> {
    await this.db
      .deleteFrom('access_tokens')
      .where('access_token', '=', record.accessToken)
      .execute();
    await this.db
      .insertInto('access_tokens')
      .values({
        access_token: record.accessToken,
        client_id: record.clientId,
        refmd_token: record.refmdToken,
        user_id: record.user.id,
        user_email: record.user.email,
        user_name: record.user.name,
        scope: JSON.stringify(record.scope),
        expires_at: record.expiresAt,
        refresh_token: record.refreshToken ?? null,
        created_at: Date.now(),
      })
      .execute();
  }

  async getAccessToken(token: string): Promise<StoredAccessToken | null> {
    const row = await this.db
      .selectFrom('access_tokens')
      .selectAll()
      .where('access_token', '=', token)
      .executeTakeFirst();
    if (!row) return null;
    return {
      accessToken: row.access_token,
      clientId: row.client_id,
      refmdToken: row.refmd_token,
      user: createUser(row),
      scope: JSON.parse(row.scope) as string[],
      expiresAt: row.expires_at,
      refreshToken: row.refresh_token ?? undefined,
    };
  }

  async deleteAccessToken(token: string): Promise<void> {
    await this.db.deleteFrom('access_tokens').where('access_token', '=', token).execute();
  }

  async saveRefreshToken(record: StoredRefreshToken): Promise<void> {
    await this.db
      .deleteFrom('refresh_tokens')
      .where('refresh_token', '=', record.refreshToken)
      .execute();
    await this.db
      .insertInto('refresh_tokens')
      .values({
        refresh_token: record.refreshToken,
        client_id: record.clientId,
        refmd_token: record.refmdToken,
        user_id: record.user.id,
        user_email: record.user.email,
        user_name: record.user.name,
        scope: JSON.stringify(record.scope),
        expires_at: record.expiresAt,
        created_at: Date.now(),
      })
      .execute();
  }

  async getRefreshToken(token: string): Promise<StoredRefreshToken | null> {
    const row = await this.db
      .selectFrom('refresh_tokens')
      .selectAll()
      .where('refresh_token', '=', token)
      .executeTakeFirst();
    if (!row) return null;
    return {
      refreshToken: row.refresh_token,
      clientId: row.client_id,
      refmdToken: row.refmd_token,
      user: createUser(row),
      scope: JSON.parse(row.scope) as string[],
      expiresAt: row.expires_at,
    };
  }

  async deleteRefreshToken(token: string): Promise<void> {
    await this.db.deleteFrom('refresh_tokens').where('refresh_token', '=', token).execute();
  }

  async deleteAccessTokensByRefreshToken(refreshToken: string): Promise<void> {
    await this.db
      .deleteFrom('access_tokens')
      .where('refresh_token', '=', refreshToken)
      .execute();
  }

  async close(): Promise<void> {
    await this.destroyFn();
  }
}

function createUser(row: {
  user_id: string;
  user_email: string;
  user_name: string;
}): RefMDUser {
  return {
    id: row.user_id,
    email: row.user_email,
    name: row.user_name,
  };
}

async function ensureSqliteDir(filePath: string): Promise<void> {
  const dir = path.dirname(filePath);
  await fs.mkdir(dir, { recursive: true });
}

async function ensureSchema(db: Kysely<TokenDatabase>): Promise<void> {
  await db.schema
    .createTable('authorization_codes')
    .ifNotExists()
    .addColumn('code', 'varchar', (col) => col.primaryKey())
    .addColumn('client_id', 'varchar', (col) => col.notNull())
    .addColumn('redirect_uri', 'varchar', (col) => col.notNull())
    .addColumn('code_challenge', 'varchar', (col) => col.notNull())
    .addColumn('code_challenge_method', 'varchar', (col) => col.notNull())
    .addColumn('refmd_token', 'text', (col) => col.notNull())
    .addColumn('user_id', 'varchar', (col) => col.notNull())
    .addColumn('user_email', 'varchar', (col) => col.notNull())
    .addColumn('user_name', 'varchar', (col) => col.notNull())
    .addColumn('scope', 'text', (col) => col.notNull())
    .addColumn('expires_at', 'bigint', (col) => col.notNull())
    .addColumn('created_at', 'bigint', (col) => col.notNull())
    .execute();

  await db.schema
    .createTable('access_tokens')
    .ifNotExists()
    .addColumn('access_token', 'varchar', (col) => col.primaryKey())
    .addColumn('client_id', 'varchar', (col) => col.notNull())
    .addColumn('refmd_token', 'text', (col) => col.notNull())
    .addColumn('user_id', 'varchar', (col) => col.notNull())
    .addColumn('user_email', 'varchar', (col) => col.notNull())
    .addColumn('user_name', 'varchar', (col) => col.notNull())
    .addColumn('scope', 'text', (col) => col.notNull())
    .addColumn('expires_at', 'bigint', (col) => col.notNull())
    .addColumn('refresh_token', 'varchar')
    .addColumn('created_at', 'bigint', (col) => col.notNull())
    .execute();

  await db.schema
    .createTable('refresh_tokens')
    .ifNotExists()
    .addColumn('refresh_token', 'varchar', (col) => col.primaryKey())
    .addColumn('client_id', 'varchar', (col) => col.notNull())
    .addColumn('refmd_token', 'text', (col) => col.notNull())
    .addColumn('user_id', 'varchar', (col) => col.notNull())
    .addColumn('user_email', 'varchar', (col) => col.notNull())
    .addColumn('user_name', 'varchar', (col) => col.notNull())
    .addColumn('scope', 'text', (col) => col.notNull())
    .addColumn('expires_at', 'bigint', (col) => col.notNull())
    .addColumn('created_at', 'bigint', (col) => col.notNull())
    .execute();
}

function normalizeSqlitePath(target: string): string {
  if (!target) return target;
  if (target.startsWith('sqlite:') || target.startsWith('file:')) {
    try {
      const url = new URL(target);
      const combined =
        url.hostname && url.hostname !== 'localhost'
          ? path.join('/', url.hostname, url.pathname)
          : url.pathname;
      return decodeURIComponent(combined);
    } catch {
      return target.replace(/^sqlite:\/\//, '').replace(/^sqlite:/, '').replace(/^file:\/*/, '');
    }
  }
  return target;
}

async function createSqliteStore(sqlitePath?: string): Promise<TokenStore> {
  const rawPath = sqlitePath ?? path.resolve(process.cwd(), 'data', 'refmd-mcp.sqlite');
  let filePath = normalizeSqlitePath(rawPath);
  if (!path.isAbsolute(filePath)) {
    filePath = path.resolve(process.cwd(), filePath);
  }
  await ensureSqliteDir(filePath);

  let sqliteModule;
  try {
    sqliteModule = await import('better-sqlite3');
  } catch (error) {
    throw new Error(
      'Failed to load better-sqlite3. Install it with `npm install better-sqlite3` when using MCP_DB_DRIVER=sqlite.',
    );
  }
  const BetterSqlite3 = sqliteModule.default ?? sqliteModule;
  const sqlite = new BetterSqlite3(filePath);
  sqlite.pragma('journal_mode = WAL');
  const dialect = new SqliteDialect({ database: sqlite });
  const db = new Kysely<TokenDatabase>({ dialect });
  await ensureSchema(db);
  return new KyselyTokenStore(db, async () => {
    await db.destroy();
    sqlite.close();
  });
}

async function createPostgresStore(url?: string): Promise<TokenStore> {
  const connectionString = url ?? process.env.MCP_DB_URL ?? process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('PostgreSQL URL required (set MCP_DB_URL or DATABASE_URL).');
  }
  let pgModule;
  try {
    pgModule = await import('pg');
  } catch (error) {
    throw new Error(
      'Failed to load pg module. Install it with `npm install pg` when using MCP_DB_DRIVER=postgres.',
    );
  }
  const pool = new pgModule.Pool({ connectionString });
  const dialect = new PostgresDialect({ pool });
  const db = new Kysely<TokenDatabase>({ dialect });
  await ensureSchema(db);
  return new KyselyTokenStore(db, async () => {
    await db.destroy();
    await pool.end();
  });
}

async function createMysqlStore(url?: string): Promise<TokenStore> {
  const connectionString = url ?? process.env.MCP_DB_URL ?? process.env.DATABASE_URL;
  if (!connectionString) {
    throw new Error('MySQL URL required (set MCP_DB_URL or DATABASE_URL).');
  }
  let mysqlModule;
  try {
    mysqlModule = await import('mysql2/promise');
  } catch (error) {
    throw new Error(
      'Failed to load mysql2 module. Install it with `npm install mysql2` when using MCP_DB_DRIVER=mysql.',
    );
  }
  const pool = mysqlModule.createPool(connectionString);
  const dialect = new MysqlDialect({ pool });
  const db = new Kysely<TokenDatabase>({ dialect });
  await ensureSchema(db);
  return new KyselyTokenStore(db, async () => {
    await db.destroy();
    await pool.end();
  });
}

export async function createTokenStore(config?: TokenStoreConfig): Promise<TokenStore> {
  if (!config || !config.driver) {
    return new InMemoryTokenStore();
  }

  const driver = config.driver.toLowerCase() as TokenStoreDriver;
  if (driver === 'sqlite') {
    return createSqliteStore(config.sqlitePath ?? config.url);
  }
  if (driver === 'postgres') {
    return createPostgresStore(config.url);
  }
  if (driver === 'mysql') {
    return createMysqlStore(config.url);
  }

  throw new Error(`Unsupported MCP_DB_DRIVER value: ${config.driver}`);
}

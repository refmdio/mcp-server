export type RefMDUser = {
  id: string;
  email: string;
  name: string;
};

export type StoredAuthorizationCode = {
  clientId: string;
  redirectUri: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256' | 'plain';
  refmdToken: string;
  user: RefMDUser;
  scope: string[];
  expiresAt: number;
};

export type StoredAccessToken = {
  accessToken: string;
  clientId: string;
  refmdToken: string;
  user: RefMDUser;
  scope: string[];
  expiresAt: number;
  refreshToken?: string;
};

export type StoredRefreshToken = {
  refreshToken: string;
  clientId: string;
  refmdToken: string;
  user: RefMDUser;
  scope: string[];
  expiresAt: number;
};

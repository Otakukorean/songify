export interface JwtPayload {
  sub: number;
  email: string;
  sessionId: number;
  iat?: number;
  exp?: number;
}

export interface GoogleProfile {
  id: string;
  displayName: string;
  name: {
    familyName: string;
    givenName: string;
  };
  emails: Array<{
    value: string;
    verified: boolean;
  }>;
  photos: Array<{
    value: string;
  }>;
  provider: string;
}

export interface SessionData {
  id: number;
  userId: number;
  sessionToken: string;
  userAgent?: string;
  ipAddress?: string;
  expiresAt: Date;
  isActive: boolean;
}

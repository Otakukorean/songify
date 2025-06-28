import { sql } from 'drizzle-orm';
import {
  pgTable,
  serial,
  varchar,
  timestamp,
  text,
  boolean,
} from 'drizzle-orm/pg-core';

export const users = pgTable('users', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  password: varchar('password', { length: 255 }), // Optional for OAuth users
  googleId: varchar('google_id', { length: 255 }).unique(),
  avatar: varchar('avatar', { length: 500 }),
  role: varchar('role', { length: 50 }).default('user'), // 'user', 'admin', 'moderator'
  permissions: varchar('permissions', { length: 1000 }).default(''), // JSON array of permissions
  isEmailVerified: boolean('is_email_verified').default(false),
  isActive: boolean('is_active').default(true),
  provider: varchar('provider', { length: 50 }).default('local'), // 'local', 'google'
  createdAt: timestamp('created_at').default(sql`CURRENT_TIMESTAMP`),
  updatedAt: timestamp('updated_at').default(sql`CURRENT_TIMESTAMP`),
});

export const sessions = pgTable('sessions', {
  id: serial('id').primaryKey(),
  userId: serial('user_id').references(() => users.id, { onDelete: 'cascade' }),
  sessionToken: varchar('session_token', { length: 255 }).notNull().unique(),
  userAgent: text('user_agent'),
  ipAddress: varchar('ip_address', { length: 45 }),
  isActive: boolean('is_active').default(true),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').default(sql`CURRENT_TIMESTAMP`),
  lastAccessedAt: timestamp('last_accessed_at').default(sql`CURRENT_TIMESTAMP`),
});

export const refreshTokens = pgTable('refresh_tokens', {
  id: serial('id').primaryKey(),
  userId: serial('user_id').references(() => users.id, { onDelete: 'cascade' }),
  token: varchar('token', { length: 255 }).notNull().unique(),
  expiresAt: timestamp('expires_at').notNull(),
  isRevoked: boolean('is_revoked').default(false),
  createdAt: timestamp('created_at').default(sql`CURRENT_TIMESTAMP`),
});

export type User = typeof users.$inferSelect;
export type NewUser = typeof users.$inferInsert;
export type Session = typeof sessions.$inferSelect;
export type NewSession = typeof sessions.$inferInsert;
export type RefreshToken = typeof refreshTokens.$inferSelect;
export type NewRefreshToken = typeof refreshTokens.$inferInsert;

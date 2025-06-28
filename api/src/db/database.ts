import { drizzle } from 'drizzle-orm/postgres-js';
import * as postgres from 'postgres';
import * as schema from './schema';
import * as dotenv from 'dotenv';

dotenv.config();

const connectionString = process.env.DATABASE_URL;
if (!connectionString) {
  throw new Error('DATABASE_URL environment variable is required');
}

// Create postgres client with proper configuration
const client = postgres(connectionString, {
  ssl: 'require', // Required for Supabase
  max: 1, // Use a single connection for development
});

export const db = drizzle(client, { schema });

export type Database = typeof db;

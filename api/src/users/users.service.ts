import { Inject, Injectable } from '@nestjs/common';
import { eq } from 'drizzle-orm';
import { Database } from '../db/database';
import { DATABASE_TOKEN } from '../db/database.module';
import { users, User, NewUser } from '../db/schema';

@Injectable()
export class UsersService {
  constructor(@Inject(DATABASE_TOKEN) private db: Database) {}

  async findAll(): Promise<User[]> {
    return this.db.select().from(users);
  }

  async findById(id: number): Promise<User | undefined> {
    const result = await this.db.select().from(users).where(eq(users.id, id));
    return result[0];
  }

  async findByEmail(email: string): Promise<User | undefined> {
    const result = await this.db
      .select()
      .from(users)
      .where(eq(users.email, email));
    return result[0];
  }

  async create(userData: NewUser): Promise<User> {
    const result = await this.db.insert(users).values(userData).returning();
    return result[0];
  }

  async update(
    id: number,
    userData: Partial<NewUser>,
  ): Promise<User | undefined> {
    const result = await this.db
      .update(users)
      .set({ ...userData })
      .where(eq(users.id, id))
      .returning();
    return result[0];
  }

  async delete(id: number): Promise<boolean> {
    const result = await this.db.delete(users).where(eq(users.id, id));
    return !!result;
  }
}

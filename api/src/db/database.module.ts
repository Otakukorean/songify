import { Global, Module } from '@nestjs/common';
import { db } from './database';

export const DATABASE_TOKEN = 'DATABASE';

@Global()
@Module({
  providers: [
    {
      provide: DATABASE_TOKEN,
      useValue: db,
    },
  ],
  exports: [DATABASE_TOKEN],
})
export class DatabaseModule {}

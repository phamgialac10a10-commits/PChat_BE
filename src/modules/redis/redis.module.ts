import { Module } from '@nestjs/common'; 
import { createClient } from "redis";
import { RedisService } from './redis.service';

@Module({
  providers: [
    {
      provide: 'REDIS_CLIENT',
      useFactory: async () => {
        const client = createClient({
          url: process.env.REDIS_URL,
        });

        client.on('error', (err) => console.error('❌ Redis error:', err));
        await client.connect();

        console.log('✅ Connected to Redis Cloud');
        return client;
      },
    },
    RedisService,
  ],
  exports: ['REDIS_CLIENT', RedisService],
})
export class RedisModule {}
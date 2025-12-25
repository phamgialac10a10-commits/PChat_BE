import { Injectable, Inject } from '@nestjs/common';
import type { RedisClientType } from 'redis';

export class RedisService {
  constructor(
    @Inject('REDIS_CLIENT') private readonly client: RedisClientType,
  ) {}

  async set(key: string, value: string, ttl?: number) {
    return this.client.set(key, value, ttl ? { EX: ttl } : undefined);
  }

  async get(key: string) {
    return this.client.get(key);
  }

  async del(key: string) {
    return this.client.del(key);
  }
}

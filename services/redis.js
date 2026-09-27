let redisClient;
let connectRedis;

if (process.env.UPSTASH_REDIS_REST_URL && process.env.UPSTASH_REDIS_REST_TOKEN) {
    const { Redis } = require('@upstash/redis');
    redisClient = new Redis({
        url: process.env.UPSTASH_REDIS_REST_URL,
        token: process.env.UPSTASH_REDIS_REST_TOKEN,
    });
    connectRedis = async () => {
        try {
            await redisClient.ping();
            console.log('Connected to Upstash Redis');
        } catch (error) {
            console.error('Error connecting to Upstash Redis:', error);
        }
    };
} else {
    const { createClient } = require('redis');
    redisClient = createClient({
        url: `redis://${process.env.REDIS_HOST || '127.0.0.1'}:${process.env.REDIS_PORT || 6379}`,
        password: process.env.REDIS_PASSWORD || undefined,
        socket: {
            reconnectStrategy: (retries) => {
                if (retries > 2) {
                    return false; // Stop reconnecting after 3 attempts
                }
                return 1000;
            }
        }
    });
    connectRedis = async () => {
        try {
            redisClient.on('error', (err) => console.error('Redis Client Error', err));
            await redisClient.connect();
            console.log('Connected to local Redis');
        } catch (error) {
            console.error('Error connecting to Redis:', error);
        }
    };
}

module.exports = { redisClient, connectRedis };

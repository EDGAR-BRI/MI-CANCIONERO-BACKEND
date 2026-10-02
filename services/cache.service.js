const { redisClient } = require('./redis');

const isUpstash = !!process.env.UPSTASH_REDIS_REST_URL;

// Local in-memory fallback cache for development when Redis server is not running
const memoryCache = new Map();

const isRedisAvailable = () => {
    return isUpstash || Boolean(redisClient?.isReady);
};

const get = async (key) => {
    if (!isRedisAvailable()) {
        const item = memoryCache.get(key);
        if (!item) return null;
        if (item.expiresAt && Date.now() > item.expiresAt) {
            memoryCache.delete(key);
            return null;
        }
        return item.value;
    }

    try {
        const data = await redisClient.get(key);
        if (!data) return null;
        if (isUpstash) return data;
        return JSON.parse(data);
    } catch (error) {
        console.error('Cache GET error:', error.message);
        return null;
    }
};

const set = async (key, value, ttlSeconds) => {
    if (!isRedisAvailable()) {
        memoryCache.set(key, {
            value,
            expiresAt: ttlSeconds ? Date.now() + ttlSeconds * 1000 : null
        });
        return;
    }

    try {
        const serialized = JSON.stringify(value);
        if (isUpstash) {
            await redisClient.set(key, serialized, { ex: ttlSeconds || undefined });
        } else {
            if (ttlSeconds) {
                await redisClient.setEx(key, ttlSeconds, serialized);
            } else {
                await redisClient.set(key, serialized);
            }
        }
    } catch (error) {
        console.error('Cache SET error:', error.message);
    }
};

const del = async (key) => {
    memoryCache.delete(key);

    if (!isRedisAvailable()) return;

    try {
        await redisClient.del(key);
    } catch (error) {
        console.error('Cache DEL error:', error.message);
    }
};

const delPattern = async (pattern) => {
    // Invalidate matching in-memory cache keys
    const regexPattern = new RegExp('^' + pattern.replace(/\*/g, '.*') + '$');
    for (const key of memoryCache.keys()) {
        if (regexPattern.test(key)) {
            memoryCache.delete(key);
        }
    }

    if (!isRedisAvailable()) return;

    try {
        const keys = await redisClient.keys(pattern);
        if (keys.length > 0) {
            if (isUpstash) {
                for (const key of keys) {
                    await redisClient.del(key);
                }
            } else {
                await redisClient.del(keys);
            }
        }
    } catch (error) {
        console.error('Cache DEL PATTERN error:', error.message);
    }
};

const getStatus = async () => {
    let connected = false;
    let type = 'Memoria Local (Fallback)';
    let pingLatencyMs = null;

    if (isUpstash) {
        try {
            const start = Date.now();
            const pong = await redisClient.ping();
            pingLatencyMs = Date.now() - start;
            if (pong === 'PONG' || pong) {
                connected = true;
                type = 'Upstash Redis (Cloud)';
            }
        } catch (e) {
            connected = false;
            type = 'Upstash Redis (Error conexión)';
        }
    } else if (redisClient) {
        try {
            if (redisClient.isReady) {
                const start = Date.now();
                const pong = await redisClient.ping();
                pingLatencyMs = Date.now() - start;
                if (pong === 'PONG') {
                    connected = true;
                    type = `Redis Local (${process.env.REDIS_HOST || '127.0.0.1'}:${process.env.REDIS_PORT || 6379})`;
                }
            } else {
                connected = false;
                type = 'Memoria Local (Servidor Redis inactivo)';
            }
        } catch (e) {
            connected = false;
            type = 'Memoria Local (Redis desconectado)';
        }
    }

    return {
        connected,
        status: connected ? 'CONECTADO' : 'DESCONECTADO',
        type,
        latencyMs: pingLatencyMs,
        memoryCacheKeys: memoryCache.size,
    };
};

module.exports = { get, set, del, delPattern, getStatus };

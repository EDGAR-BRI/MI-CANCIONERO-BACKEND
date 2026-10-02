const cache = require('../services/cache.service');

/**
 * Rate limiter middleware for PDF downloads.
 * Limits users/guests to a maximum of 3 downloads per 5 minutes (300 seconds).
 */
const pdfDownloadRateLimiter = async (req, res, next) => {
    try {
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0].trim() ||
            req.ip ||
            req.socket?.remoteAddress ||
            'unknown';

        const identifier = req.user?.id ? `user:${req.user.id}` : `ip:${clientIp}`;
        const cacheKey = `ratelimit:pdf:${identifier}`;
        const WINDOW_SECONDS = 300; // 5 minutes
        const MAX_DOWNLOADS = 3;

        const current = await cache.get(cacheKey);
        const now = Date.now();

        if (!current) {
            // First download in the 5-minute window
            await cache.set(cacheKey, { count: 1, resetAt: now + WINDOW_SECONDS * 1000 }, WINDOW_SECONDS);
            res.setHeader('X-RateLimit-Limit', String(MAX_DOWNLOADS));
            res.setHeader('X-RateLimit-Remaining', String(MAX_DOWNLOADS - 1));
            return next();
        }

        if (current.count >= MAX_DOWNLOADS) {
            const retryAfter = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
            res.setHeader('X-RateLimit-Limit', String(MAX_DOWNLOADS));
            res.setHeader('X-RateLimit-Remaining', '0');
            res.setHeader('Retry-After', String(retryAfter));
            return res.status(429).json({
                error: 'Has alcanzado el límite de descargas (máximo 3 cada 5 minutos). Por favor espera un momento.',
                retryAfter
            });
        }

        // Increment count and update remaining TTL
        current.count += 1;
        const remainingSeconds = Math.max(1, Math.ceil((current.resetAt - now) / 1000));
        await cache.set(cacheKey, current, remainingSeconds);

        res.setHeader('X-RateLimit-Limit', String(MAX_DOWNLOADS));
        res.setHeader('X-RateLimit-Remaining', String(Math.max(0, MAX_DOWNLOADS - current.count)));
        return next();
    } catch (err) {
        console.error('Error in pdfDownloadRateLimiter:', err);
        // In case of cache failure, do not block the user
        next();
    }
};

module.exports = { pdfDownloadRateLimiter };

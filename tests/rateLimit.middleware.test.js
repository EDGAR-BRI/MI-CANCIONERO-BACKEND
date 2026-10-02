const cache = require('../services/cache.service');
const { pdfDownloadRateLimiter } = require('../middleware/rateLimit.middleware');

describe('PDF Download Rate Limiter Middleware', () => {
    let req;
    let res;
    let next;

    beforeEach(() => {
        vi.restoreAllMocks();
        req = {
            user: { id: 42 },
            headers: {},
            ip: '127.0.0.1',
            socket: {}
        };
        res = {
            setHeader: vi.fn(),
            status: vi.fn().mockReturnThis(),
            json: vi.fn().mockReturnThis()
        };
        next = vi.fn();
    });

    it('debe permitir la primera descarga y configurar contador en cache', async () => {
        vi.spyOn(cache, 'get').mockResolvedValue(null);
        const setSpy = vi.spyOn(cache, 'set').mockResolvedValue(true);

        await pdfDownloadRateLimiter(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '3');
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', '2');
        expect(setSpy).toHaveBeenCalledWith(
            'ratelimit:pdf:user:42',
            expect.objectContaining({ count: 1 }),
            300
        );
    });

    it('debe permitir la segunda y tercera descarga incrementando el contador', async () => {
        const resetAt = Date.now() + 200 * 1000;
        vi.spyOn(cache, 'get').mockResolvedValue({ count: 2, resetAt });
        const setSpy = vi.spyOn(cache, 'set').mockResolvedValue(true);

        await pdfDownloadRateLimiter(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '3');
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', '0');
        expect(setSpy).toHaveBeenCalledWith(
            'ratelimit:pdf:user:42',
            expect.objectContaining({ count: 3 }),
            expect.any(Number)
        );
    });

    it('debe bloquear con 429 cuando se excede el límite de 3 descargas en 5 minutos', async () => {
        const resetAt = Date.now() + 180 * 1000;
        vi.spyOn(cache, 'get').mockResolvedValue({ count: 3, resetAt });

        await pdfDownloadRateLimiter(req, res, next);

        expect(next).not.toHaveBeenCalled();
        expect(res.status).toHaveBeenCalledWith(429);
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Limit', '3');
        expect(res.setHeader).toHaveBeenCalledWith('X-RateLimit-Remaining', '0');
        expect(res.setHeader).toHaveBeenCalledWith('Retry-After', expect.any(String));
        expect(res.json).toHaveBeenCalledWith(
            expect.objectContaining({
                error: expect.stringContaining('límite de descargas'),
                retryAfter: expect.any(Number)
            })
        );
    });

    it('debe usar la IP cuando el usuario no está autenticado', async () => {
        req.user = null;
        req.ip = '192.168.1.50';
        vi.spyOn(cache, 'get').mockResolvedValue(null);
        const setSpy = vi.spyOn(cache, 'set').mockResolvedValue(true);

        await pdfDownloadRateLimiter(req, res, next);

        expect(next).toHaveBeenCalled();
        expect(setSpy).toHaveBeenCalledWith(
            'ratelimit:pdf:ip:192.168.1.50',
            expect.objectContaining({ count: 1 }),
            300
        );
    });
});

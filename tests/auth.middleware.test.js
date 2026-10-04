import { describe, it, expect, vi, beforeEach } from 'vitest';
const { authorizeAdmin, authorizePermission } = require('../middleware/auth.middleware');

describe('Auth Middleware (back/middleware/auth.middleware)', () => {
    let req;
    let res;
    let next;

    beforeEach(() => {
        req = {};
        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn().mockReturnThis()
        };
        next = vi.fn();
    });

    describe('authorizeAdmin', () => {
        it('debe llamar a next() si el usuario tiene rol ADMIN', () => {
            req.user = { id: 'admin-1', role: 'ADMIN' };

            authorizeAdmin(req, res, next);

            expect(next).toHaveBeenCalledTimes(1);
            expect(res.status).not.toHaveBeenCalled();
        });

        it('debe retornar 403 si el usuario tiene un rol distinto a ADMIN', () => {
            req.user = { id: 'user-1', role: 'USER' };

            authorizeAdmin(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: 'Admin privileges required' });
        });

        it('debe retornar 403 si no hay usuario en la petición', () => {
            req.user = undefined;

            authorizeAdmin(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(403);
        });
    });

    describe('authorizePermission', () => {
        it('debe retornar 401 si no hay usuario autenticado en la petición', () => {
            const middleware = authorizePermission('SONG_CREATE');
            middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: 'User not authenticated' });
        });

        it('debe permitir el acceso llamando a next() si el usuario es ADMIN, aunque no tenga el permiso explícito', () => {
            req.user = { id: 'admin-1', role: 'ADMIN', permissions: [] };

            const middleware = authorizePermission('SONG_DELETE');
            middleware(req, res, next);

            expect(next).toHaveBeenCalledTimes(1);
            expect(res.status).not.toHaveBeenCalled();
        });

        it('debe permitir el acceso si el usuario tiene el permiso asignado', () => {
            req.user = {
                id: 'musico-1',
                role: 'USER',
                permissions: ['SONG_CREATE', 'SONG_READ']
            };

            const middleware = authorizePermission('SONG_CREATE');
            middleware(req, res, next);

            expect(next).toHaveBeenCalledTimes(1);
            expect(res.status).not.toHaveBeenCalled();
        });

        it('debe retornar 403 si el usuario carece del permiso requerido', () => {
            req.user = {
                id: 'musico-1',
                role: 'USER',
                permissions: ['SONG_READ']
            };

            const middleware = authorizePermission('SONG_DELETE');
            middleware(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: 'Missing permission: SONG_DELETE' });
        });
    });

    describe('authenticateToken', () => {
        const { authenticateToken } = require('../middleware/auth.middleware');

        it('debe retornar 401 si no hay token ni refresh_token en cookies o headers', async () => {
            req.cookies = {};
            req.headers = {};

            await authenticateToken(req, res, next);

            expect(next).not.toHaveBeenCalled();
            expect(res.status).toHaveBeenCalledWith(401);
            expect(res.json).toHaveBeenCalledWith({ error: 'Authentication required' });
        });
    });
});

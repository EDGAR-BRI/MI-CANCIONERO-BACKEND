const prisma = require('../prismaClient');
const cache = require('../services/cache.service');
const misaController = require('../controllers/misa.controller');

describe('Misa Controller - Opción 1: Privacidad estricta por cuenta', () => {
    let req;
    let res;

    beforeEach(() => {
        vi.restoreAllMocks();
        vi.spyOn(cache, 'get').mockResolvedValue(null);
        vi.spyOn(cache, 'set').mockResolvedValue(true);
        vi.spyOn(cache, 'delPattern').mockResolvedValue(true);

        vi.spyOn(prisma.misa, 'findUnique').mockResolvedValue(null);
        vi.spyOn(prisma.misa, 'findMany').mockResolvedValue([]);
        vi.spyOn(prisma.misa, 'create').mockResolvedValue({});
        vi.spyOn(prisma.misa, 'update').mockResolvedValue({});
        vi.spyOn(prisma.misa, 'delete').mockResolvedValue({});

        vi.spyOn(prisma.ministryMember, 'findUnique').mockResolvedValue(null);

        req = {
            params: { id: '1' },
            body: {},
            query: {}
        };
        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn().mockReturnThis()
        };
    });

    describe('getMisaById', () => {
        it('debe retornar 404 si la misa no existe', async () => {
            prisma.misa.findUnique.mockResolvedValue(null);

            await misaController.getMisaById(req, res);

            expect(res.status).toHaveBeenCalledWith(404);
            expect(res.json).toHaveBeenCalledWith({ error: 'Misa no encontrada' });
        });

        it('debe permitir ver una misa PÚBLICA a un usuario anónimo (canEdit: false)', async () => {
            const mockMisa = {
                id: 1,
                title: 'Misa de Pascua',
                visibility: 'PUBLIC',
                userId: 10,
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);

            await misaController.getMisaById(req, res);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    id: 1,
                    visibility: 'PUBLIC',
                    isOwner: false,
                    canEdit: false
                })
            );
        });

        it('debe permitir canEdit: true si el usuario autenticado es el creador de la misa pública', async () => {
            req.user = { id: 10, email: 'owner@test.com' };
            const mockMisa = {
                id: 1,
                title: 'Misa de Pascua',
                visibility: 'PUBLIC',
                userId: 10,
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);

            await misaController.getMisaById(req, res);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    isOwner: true,
                    canEdit: true
                })
            );
        });

        it('debe denegar (403) el acceso a una misa PRIVADA si el usuario es anónimo con requiresAuth: true', async () => {
            req.user = undefined;
            const mockMisa = {
                id: 1,
                title: 'Misa de Ensayo',
                visibility: 'PRIVATE',
                userId: 10,
                ministryId: 5,
                ministry: { id: 5, name: 'Coro Santa Cecilia' },
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);

            await misaController.getMisaById(req, res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({
                error: 'Esta misa es privada del grupo "Coro Santa Cecilia".',
                isPrivate: true,
                requiresAuth: true,
                ministryName: 'Coro Santa Cecilia'
            });
        });

        it('debe denegar (403) el acceso a una misa PRIVADA si el usuario no es miembro del ministerio', async () => {
            req.user = { id: 99, email: 'other@test.com' };
            const mockMisa = {
                id: 1,
                title: 'Misa de Ensayo',
                visibility: 'PRIVATE',
                userId: 10,
                ministryId: 5,
                ministry: { id: 5, name: 'Coro Santa Cecilia' },
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);
            prisma.ministryMember.findUnique.mockResolvedValue(null);

            await misaController.getMisaById(req, res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({
                error: 'Esta misa es privada del grupo "Coro Santa Cecilia".',
                isPrivate: true,
                requiresAuth: false,
                ministryName: 'Coro Santa Cecilia'
            });
        });

        it('debe permitir ver y editar (200) una misa PRIVADA a un miembro ACTIVO del ministerio', async () => {
            req.user = { id: 25, email: 'member@test.com' };
            const mockMisa = {
                id: 1,
                title: 'Misa de Ensayo',
                visibility: 'PRIVATE',
                userId: 10,
                ministryId: 5,
                ministry: { id: 5, name: 'Coro Santa Cecilia' },
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);
            prisma.ministryMember.findUnique.mockResolvedValue({
                ministryId: 5,
                userId: 25,
                status: 'ACTIVE',
                role: 'MEMBER'
            });

            await misaController.getMisaById(req, res);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    id: 1,
                    canEdit: true,
                    isOwner: false
                })
            );
        });

        it('debe permitir ver y editar (200) una misa PRIVADA a un usuario con rol ADMIN', async () => {
            req.user = { id: 999, role: 'ADMIN', email: 'admin@test.com' };
            const mockMisa = {
                id: 1,
                title: 'Misa Privada',
                visibility: 'PRIVATE',
                userId: 10,
                ministryId: null,
                misaMoments: [{ id: 1, moment: { id: 1, nombre: 'Entrada' } }],
                misaSongs: []
            };
            prisma.misa.findUnique.mockResolvedValue(mockMisa);

            await misaController.getMisaById(req, res);

            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({
                    id: 1,
                    canEdit: true
                })
            );
        });
    });

    describe('updateMisa', () => {
        it('debe rechazar (403) si el usuario no tiene permisos sobre la misa', async () => {
            req.user = { id: 50, email: 'random@test.com' };
            req.body = { title: 'Nuevo Titulo' };
            prisma.misa.findUnique.mockResolvedValue({
                id: 1,
                userId: 10,
                ministryId: null
            });

            await misaController.updateMisa(req, res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: 'Not authorized to update this misa' });
        });

        it('debe actualizar exitosamente si el usuario es miembro activo del ministerio de la misa', async () => {
            req.user = { id: 30, email: 'active@test.com' };
            req.body = { title: 'Misa Actualizada', visibility: 'PUBLIC' };
            prisma.misa.findUnique.mockResolvedValue({
                id: 1,
                userId: 10,
                ministryId: 8
            });
            prisma.ministryMember.findUnique.mockResolvedValue({
                ministryId: 8,
                userId: 30,
                status: 'ACTIVE'
            });
            prisma.misa.update.mockResolvedValue({
                id: 1,
                title: 'Misa Actualizada',
                visibility: 'PUBLIC'
            });

            await misaController.updateMisa(req, res);

            expect(prisma.misa.update).toHaveBeenCalled();
            expect(res.json).toHaveBeenCalledWith(
                expect.objectContaining({ title: 'Misa Actualizada' })
            );
        });
    });

    describe('deleteMisa', () => {
        it('debe retornar 403 si un miembro activo regular (no admin de grupo) intenta eliminar la misa', async () => {
            req.user = { id: 30, role: 'USER' };
            prisma.misa.findUnique.mockResolvedValue({
                id: 1,
                userId: 10,
                ministryId: 8
            });
            prisma.ministryMember.findUnique.mockResolvedValue({
                ministryId: 8,
                userId: 30,
                status: 'ACTIVE',
                role: 'MEMBER'
            });

            await misaController.deleteMisa(req, res);

            expect(res.status).toHaveBeenCalledWith(403);
            expect(res.json).toHaveBeenCalledWith({ error: 'Not authorized to delete this misa' });
        });

        it('debe permitir eliminar la misa si el usuario es ADMIN del ministerio', async () => {
            req.user = { id: 30, role: 'USER' };
            prisma.misa.findUnique.mockResolvedValue({
                id: 1,
                userId: 10,
                ministryId: 8
            });
            prisma.ministryMember.findUnique.mockResolvedValue({
                ministryId: 8,
                userId: 30,
                status: 'ACTIVE',
                role: 'ADMIN'
            });
            prisma.misa.delete.mockResolvedValue({ id: 1 });

            await misaController.deleteMisa(req, res);

            expect(prisma.misa.delete).toHaveBeenCalledWith({ where: { id: 1 } });
            expect(res.json).toHaveBeenCalledWith({ message: 'Misa deleted successfully' });
        });
    });
});

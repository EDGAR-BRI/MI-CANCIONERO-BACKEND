const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');
const authController = require('../controllers/auth.controller');

describe('Profile Password Update (back/controllers/auth.controller.js)', () => {
    let req;
    let res;

    beforeEach(() => {
        vi.restoreAllMocks();

        req = {
            user: { id: 10, role: 'USER' },
            body: {}
        };
        res = {
            status: vi.fn().mockReturnThis(),
            json: vi.fn().mockReturnThis(),
            cookie: vi.fn()
        };
    });

    it('debe rechazar nueva contraseña menor a 6 caracteres con 400', async () => {
        req.body = { newPassword: '123' };

        await authController.updateProfile(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'La nueva contraseña debe tener al menos 6 caracteres.'
        });
    });

    it('debe rechazar si se envía contraseña actual pero no la nueva contraseña', async () => {
        req.body = { currentPassword: 'claveActual123' };

        await authController.updateProfile(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Debes ingresar una nueva contraseña.'
        });
    });

    it('debe exigir contraseña actual si el usuario no es de Google y quiere cambiar contraseña', async () => {
        req.body = { newPassword: 'nuevaClaveSegura123' };

        vi.spyOn(prisma.user, 'findUnique').mockResolvedValue({
            id: 10,
            email: 'usuario@ejemplo.com',
            password: '$2a$10$hashedCurrentPassword',
            googleId: null
        });

        await authController.updateProfile(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'Debes ingresar tu contraseña actual para cambiarla.'
        });
    });

    it('debe rechazar si la contraseña actual no coincide', async () => {
        req.body = {
            currentPassword: 'claveErronea',
            newPassword: 'nuevaClaveSegura123'
        };

        const currentHashed = await bcrypt.hash('claveVerdadera', 10);
        vi.spyOn(prisma.user, 'findUnique').mockResolvedValue({
            id: 10,
            email: 'usuario@ejemplo.com',
            password: currentHashed,
            googleId: null
        });

        await authController.updateProfile(req, res);

        expect(res.status).toHaveBeenCalledWith(400);
        expect(res.json).toHaveBeenCalledWith({
            error: 'La contraseña actual es incorrecta.'
        });
    });

    it('debe actualizar la contraseña exitosamente cuando la contraseña actual es válida', async () => {
        req.body = {
            name: 'Nombre Modificado',
            currentPassword: 'claveCorrecta123',
            newPassword: 'nuevaClaveSegura456'
        };

        const currentHashed = await bcrypt.hash('claveCorrecta123', 10);
        vi.spyOn(prisma.user, 'findUnique').mockResolvedValue({
            id: 10,
            email: 'usuario@ejemplo.com',
            password: currentHashed,
            googleId: null
        });

        vi.spyOn(prisma.user, 'update').mockResolvedValue({
            id: 10,
            name: 'Nombre Modificado',
            email: 'usuario@ejemplo.com',
            avatarUrl: null,
            phoneNumber: '+584121234567',
            googleId: null,
            role: { name: 'USER', permissions: [] }
        });

        await authController.updateProfile(req, res);

        expect(prisma.user.update).toHaveBeenCalledWith(expect.objectContaining({
            where: { id: 10 },
            data: expect.objectContaining({
                name: 'Nombre Modificado',
                password: expect.any(String)
            })
        }));

        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            message: 'Perfil actualizado exitosamente.',
            token: expect.any(String),
            user: expect.objectContaining({
                name: 'Nombre Modificado',
                isGoogleUser: false
            })
        }));
    });

    it('debe permitir a usuarios registrados con Google establecer contraseña sin ingresar la actual', async () => {
        req.body = {
            newPassword: 'miNuevaClaveDeGoogle123'
        };

        vi.spyOn(prisma.user, 'findUnique').mockResolvedValue({
            id: 10,
            email: 'googleuser@gmail.com',
            password: '$2a$10$randomGeneratedPassword',
            googleId: 'google-sub-id-123'
        });

        vi.spyOn(prisma.user, 'update').mockResolvedValue({
            id: 10,
            name: 'Google User',
            email: 'googleuser@gmail.com',
            avatarUrl: null,
            phoneNumber: null,
            googleId: 'google-sub-id-123',
            role: { name: 'USER', permissions: [] }
        });

        await authController.updateProfile(req, res);

        expect(prisma.user.update).toHaveBeenCalledWith(expect.objectContaining({
            where: { id: 10 },
            data: expect.objectContaining({
                password: expect.any(String)
            })
        }));

        expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
            message: 'Perfil actualizado exitosamente.',
            user: expect.objectContaining({
                isGoogleUser: true
            })
        }));
    });
});

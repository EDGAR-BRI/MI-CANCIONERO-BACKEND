import { describe, it, expect } from 'vitest';
const jwtService = require('../services/jwt.service');

describe('JWT Service (back/services/jwt.service)', () => {
    const mockUserWithRoleObject = {
        id: 'usr-123',
        email: 'musico@ejemplo.com',
        name: 'Músico Alabanza',
        avatarUrl: 'https://example.com/avatar.png',
        role: {
            name: 'DIRECTOR',
            permissions: [
                { name: 'SONG_CREATE' },
                { name: 'SONG_EDIT' },
                { name: 'MISA_MANAGE' }
            ]
        }
    };

    const mockUserWithStringRole = {
        id: 'usr-456',
        email: 'coro@ejemplo.com',
        name: 'Corista',
        role: 'USER',
        permissions: ['SONG_READ']
    };

    describe('generateTokens', () => {
        it('debe generar access token y refresh token válidos para un usuario con rol como objeto', () => {
            const { token, refreshToken } = jwtService.generateTokens(mockUserWithRoleObject);

            expect(typeof token).toBe('string');
            expect(typeof refreshToken).toBe('string');
            expect(token.length).toBeGreaterThan(20);
            expect(refreshToken.length).toBeGreaterThan(20);

            const decoded = jwtService.verifyToken(token);
            expect(decoded).not.toBeNull();
            expect(decoded.id).toBe(mockUserWithRoleObject.id);
            expect(decoded.email).toBe(mockUserWithRoleObject.email);
            expect(decoded.name).toBe(mockUserWithRoleObject.name);
            expect(decoded.role).toBe('DIRECTOR');
            expect(decoded.permissions).toEqual(['SONG_CREATE', 'SONG_EDIT', 'MISA_MANAGE']);
        });

        it('debe generar tokens válidos cuando el rol es un string y permissions es array de strings', () => {
            const { token, refreshToken } = jwtService.generateTokens(mockUserWithStringRole);

            const decoded = jwtService.verifyToken(token);
            expect(decoded).not.toBeNull();
            expect(decoded.role).toBe('USER');
            expect(decoded.permissions).toEqual(['SONG_READ']);
        });

        it('debe asignar rol por defecto USER si el usuario no tiene rol especificado', () => {
            const userWithoutRole = {
                id: 'usr-789',
                email: 'norole@ejemplo.com',
                name: 'Sin Rol'
            };

            const { token } = jwtService.generateTokens(userWithoutRole);
            const decoded = jwtService.verifyToken(token);
            expect(decoded.role).toBe('USER');
            expect(decoded.permissions).toEqual([]);
        });
    });

    describe('verifyToken', () => {
        it('debe verificar y decodificar correctamente un token válido', () => {
            const { token } = jwtService.generateTokens(mockUserWithRoleObject);
            const decoded = jwtService.verifyToken(token);

            expect(decoded).toBeTruthy();
            expect(decoded.id).toBe(mockUserWithRoleObject.id);
            expect(decoded.email).toBe(mockUserWithRoleObject.email);
        });

        it('debe retornar null para tokens manipulados, expirados o inválidos', () => {
            expect(jwtService.verifyToken('token.invalido.falso')).toBeNull();
            expect(jwtService.verifyToken('')).toBeNull();
            expect(jwtService.verifyToken(null)).toBeNull();
        });
    });

    describe('verifyRefreshToken', () => {
        it('debe verificar un refresh token válido con type: "refresh"', () => {
            const { refreshToken } = jwtService.generateTokens(mockUserWithRoleObject);
            const decoded = jwtService.verifyRefreshToken(refreshToken);

            expect(decoded).toBeTruthy();
            expect(decoded.id).toBe(mockUserWithRoleObject.id);
            expect(decoded.type).toBe('refresh');
        });

        it('debe rechazar un access token cuando se pasa a verifyRefreshToken', () => {
            const { token } = jwtService.generateTokens(mockUserWithRoleObject);
            // El access token no tiene type: 'refresh'
            const decoded = jwtService.verifyRefreshToken(token);
            expect(decoded).toBeNull();
        });

        it('debe retornar null para refresh tokens corruptos o inválidos', () => {
            expect(jwtService.verifyRefreshToken('refresh.invalido')).toBeNull();
            expect(jwtService.verifyRefreshToken(null)).toBeNull();
        });
    });
});

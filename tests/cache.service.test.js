import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
const cache = require('../services/cache.service');

describe('Cache Service (back/services/cache.service)', () => {
    beforeEach(async () => {
        // Limpiar la caché en memoria antes de cada prueba
        await cache.delPattern('*');
    });

    afterEach(async () => {
        await cache.delPattern('*');
    });

    describe('Operaciones en memoria (Memory Cache Fallback)', () => {
        it('debe almacenar y recuperar un valor primitivo u objeto', async () => {
            const key = 'test:song:1';
            const value = { id: 1, title: 'Pescador de hombres', key: 'D' };

            await cache.set(key, value);
            const cached = await cache.get(key);

            expect(cached).toEqual(value);
        });

        it('debe retornar null para una clave inexistente', async () => {
            const cached = await cache.get('test:clave:no:existe');
            expect(cached).toBeNull();
        });

        it('debe eliminar una clave específica con del()', async () => {
            const key = 'test:temp';
            await cache.set(key, { data: 123 });

            let value = await cache.get(key);
            expect(value).toEqual({ data: 123 });

            await cache.del(key);
            value = await cache.get(key);
            expect(value).toBeNull();
        });

        it('debe expirar un valor cuando su TTL en segundos ha transcurrido', async () => {
            const key = 'test:expiring';
            const value = 'temporal';
            // TTL de 1 segundo
            await cache.set(key, value, 1);

            // Inmediatamente después existe
            let cached = await cache.get(key);
            expect(cached).toBe(value);

            // Simular paso del tiempo adelantando Date.now
            const realDateNow = Date.now;
            try {
                // Adelantar 1.5 segundos
                Date.now = () => realDateNow() + 1500;
                cached = await cache.get(key);
                expect(cached).toBeNull();
            } finally {
                Date.now = realDateNow;
            }
        });

        it('debe eliminar por patrón con delPattern() sin afectar otras claves', async () => {
            // Guardar canciones y categorías
            await cache.set('songs:1', { title: 'Canción 1' });
            await cache.set('songs:2', { title: 'Canción 2' });
            await cache.set('songs:list:all', [{ id: 1 }, { id: 2 }]);
            await cache.set('categories:all', [{ id: 1, name: 'Entrada' }]);
            await cache.set('user:profile:10', { name: 'Juan' });

            // Invalidar sólo canciones
            await cache.delPattern('songs:*');

            // Claves de songs deben estar eliminadas
            expect(await cache.get('songs:1')).toBeNull();
            expect(await cache.get('songs:2')).toBeNull();
            expect(await cache.get('songs:list:all')).toBeNull();

            // Otras claves deben seguir intactas
            expect(await cache.get('categories:all')).toEqual([{ id: 1, name: 'Entrada' }]);
            expect(await cache.get('user:profile:10')).toEqual({ name: 'Juan' });
        });
    });
});

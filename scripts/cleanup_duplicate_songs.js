const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

async function main() {
    console.log('--- Iniciando limpieza y unificación de canciones duplicadas ---');

    // 1. Mapeo de duplicados conocidos: [ID duplicado] -> [ID original que se conserva]
    const duplicatesMap = [
        { duplicateId: 4, keeperId: 1, title: 'Tu Fidelidad' },
        { duplicateId: 5, keeperId: 2, title: 'Renuévame' },
        { duplicateId: 6, keeperId: 3, title: 'Cantaré al Señor por siempre' }
    ];

    for (const { duplicateId, keeperId, title } of duplicatesMap) {
        console.log(`\nProcesando "${title}": migrando referencias de Song #${duplicateId} a Song #${keeperId}...`);

        // A. Migrar referencias en MisaSong
        const misasUpdated = await prisma.misaSong.updateMany({
            where: { songId: duplicateId },
            data: { songId: keeperId }
        });
        console.log(`  ✓ ${misasUpdated.count} registro(s) de MisaSong actualizados a Song #${keeperId}`);

        // B. Copiar categorías asociadas si el duplicado tenía alguna que el original no
        const dupSong = await prisma.song.findUnique({
            where: { id: duplicateId },
            include: { categories: true }
        });

        if (dupSong && dupSong.categories.length > 0) {
            await prisma.song.update({
                where: { id: keeperId },
                data: {
                    categories: {
                        connect: dupSong.categories.map(c => ({ id: c.id }))
                    }
                }
            });
            console.log(`  ✓ Categorías sincronizadas en Song #${keeperId}`);
        }

        // C. Eliminar el registro duplicado
        if (dupSong) {
            await prisma.song.delete({
                where: { id: duplicateId }
            });
            console.log(`  ✓ Song duplicada #${duplicateId} eliminada.`);
        }
    }

    // 2. Limpiar caracteres invisibles/soft-hyphens en canción #8 si existen
    const song8 = await prisma.song.findUnique({ where: { id: 8 } });
    if (song8) {
        const cleanTitle = song8.title.replace(/\u00ad/g, '').trim();
        const cleanContent = song8.content.replace(/\u00ad/g, '');
        if (cleanTitle !== song8.title || cleanContent !== song8.content) {
            await prisma.song.update({
                where: { id: 8 },
                data: {
                    title: cleanTitle,
                    content: cleanContent
                }
            });
            console.log('\n✓ Caracteres invisibles (soft-hyphen) corregidos en Song #8 ("Dios está aquí").');
        }
    }

    // 3. Limpiar caché en Redis/Memoria local
    try {
        await cache.delPattern('songs:*');
        await cache.delPattern('authors:*');
        await cache.del('stats');
        console.log('\n✓ Caché invalidado.');
    } catch (e) {
        console.warn('Advertencia al invalidar caché:', e.message);
    }

    // 4. Reporte final
    const remainingSongs = await prisma.song.findMany({
        select: { id: true, title: true, key: true, author: { select: { name: true } }, categories: { select: { name: true } } },
        orderBy: { id: 'asc' }
    });

    console.log(`\n========================================`);
    console.log(`Total de canciones únicas en BD: ${remainingSongs.length}`);
    console.log(`========================================`);
    remainingSongs.forEach(s => {
        const cats = s.categories.map(c => c.name).join(', ');
        console.log(`[#${s.id}] "${s.title}" - ${s.author?.name || 'Desconocido'} (${s.key}) [${cats}]`);
    });
}

main()
    .catch(err => {
        console.error('Error durante la limpieza:', err);
        process.exit(1);
    })
    .finally(() => prisma.$disconnect());

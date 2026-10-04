/**
 * Script para sanitizar y formatear el contenido de todas las canciones
 * existentes en la base de datos de PostgreSQL.
 *
 * Elimina saltos de línea artificiales (líneas de 1-3 palabras huérfanas),
 * normaliza retornos de carro (\r\n) y limpia espacios innecesarios.
 *
 * Uso: node back/scripts/sanitize_existing_songs.js
 */

const prisma = require('../prismaClient');
const cache = require('../services/cache.service');
const { sanitizeSongContent } = require('../utils/songSanitizer');

async function main() {
    console.log('🔍 Iniciando sanitización de canciones en la base de datos...');

    const songs = await prisma.song.findMany({
        select: {
            id: true,
            title: true,
            content: true
        }
    });

    console.log(`📋 Total de canciones encontradas: ${songs.length}`);

    let updatedCount = 0;

    for (const song of songs) {
        if (!song.content) continue;

        const sanitized = sanitizeSongContent(song.content);

        if (sanitized !== song.content) {
            await prisma.song.update({
                where: { id: song.id },
                data: { content: sanitized }
            });
            console.log(`✅ [ID ${song.id}] «${song.title}» formateada correctamente.`);
            updatedCount++;
        }
    }

    if (updatedCount > 0) {
        console.log('🧹 Limpiando caché de canciones...');
        await cache.delPattern('songs:list:*');
        await cache.delPattern('songs:detail:*');
    }

    console.log(`\n🎉 Proceso completado: ${updatedCount} de ${songs.length} canciones fueron actualizadas.`);
}

main()
    .then(async () => {
        await prisma.$disconnect();
        process.exit(0);
    })
    .catch(async (e) => {
        console.error('❌ Error durante la sanitización:', e);
        await prisma.$disconnect();
        process.exit(1);
    });

const prisma = require('../prismaClient');

async function migrateArtistsToAuthors() {
    console.log('--- Migrando Artistas (String) a Autores (Tabla Author) ---');
    try {
        // 1. Asegurar autor por defecto 'Desconocido'
        let defaultAuthor = await prisma.author.findUnique({
            where: { name: 'Desconocido' }
        });

        if (!defaultAuthor) {
            defaultAuthor = await prisma.author.create({
                data: { name: 'Desconocido' }
            });
            console.log('✅ Autor por defecto "Desconocido" creado.');
        } else {
            console.log('ℹ️ Autor por defecto "Desconocido" ya existe (ID:', defaultAuthor.id, ').');
        }

        // 2. Obtener todas las canciones
        const songs = await prisma.song.findMany({
            select: {
                id: true,
                title: true,
                artist: true,
                authorId: true
            }
        });

        console.log(`Encontradas ${songs.length} canciones para procesar.`);

        let migratedCount = 0;
        const authorCache = new Map();
        authorCache.set('desconocido', defaultAuthor);

        for (const song of songs) {
            const rawArtist = (song.artist || '').trim();
            const authorName = rawArtist.length > 0 ? rawArtist : 'Desconocido';
            const cacheKey = authorName.toLowerCase();

            let targetAuthor = authorCache.get(cacheKey);

            if (!targetAuthor) {
                // Buscar en DB o crear
                targetAuthor = await prisma.author.findFirst({
                    where: {
                        name: {
                            equals: authorName,
                            mode: 'insensitive'
                        }
                    }
                });

                if (!targetAuthor) {
                    targetAuthor = await prisma.author.create({
                        data: { name: authorName }
                    });
                    console.log(`➕ Nuevo Autor creado: "${targetAuthor.name}" (ID: ${targetAuthor.id})`);
                }

                authorCache.set(cacheKey, targetAuthor);
            }

            // Asignar authorId a la canción
            await prisma.song.update({
                where: { id: song.id },
                data: {
                    authorId: targetAuthor.id
                }
            });

            console.log(`🎵 Canción "${song.title}" (ID: ${song.id}) asignada al autor "${targetAuthor.name}" (ID: ${targetAuthor.id})`);
            migratedCount++;
        }

        console.log(`\n🎉 Migración completada exitosamente: ${migratedCount} canciones asignadas a sus respectivos autores.`);

        const totalAuthors = await prisma.author.count();
        console.log(`Total de autores en base de datos: ${totalAuthors}`);
    } catch (error) {
        console.error('❌ Error durante la migración de autores:', error);
        process.exit(1);
    } finally {
        await prisma.$disconnect();
    }
}

migrateArtistsToAuthors();

const prisma = require('../prismaClient');

async function migrateArtistsToAuthors() {
    console.log('--- Migrando Artistas a Autores (Tabla Author) ---');
    try {
        // 1. Asegurar autor por defecto 'Desconocido'
        await prisma.$executeRawUnsafe(`
            INSERT INTO authors (name, "createdAt", "updatedAt")
            VALUES ('Desconocido', NOW(), NOW())
            ON CONFLICT (name) DO NOTHING;
        `);

        const defaultAuthor = await prisma.author.findUnique({
            where: { name: 'Desconocido' }
        });
        const defaultAuthorId = defaultAuthor ? defaultAuthor.id : 1;
        console.log(`ℹ️ Autor por defecto "Desconocido" ID: ${defaultAuthorId}`);

        // 2. Verificar si la columna "artist" existe físicamente en la tabla songs
        const columns = await prisma.$queryRawUnsafe(`
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name = 'songs' AND column_name = 'artist';
        `);

        if (Array.isArray(columns) && columns.length > 0) {
            console.log('🔍 Columna "artist" encontrada en la tabla "songs". Extrayendo autores existentes...');

            // Crear autores únicos desde la columna artist
            await prisma.$executeRawUnsafe(`
                INSERT INTO authors (name, "createdAt", "updatedAt")
                SELECT DISTINCT TRIM(artist), NOW(), NOW()
                FROM songs
                WHERE artist IS NOT NULL AND TRIM(artist) <> ''
                ON CONFLICT (name) DO NOTHING;
            `);

            // Asignar authorId según artist
            const updatedFromArtist = await prisma.$executeRawUnsafe(`
                UPDATE songs s
                SET "authorId" = a.id
                FROM authors a
                WHERE s."authorId" IS NULL 
                  AND TRIM(s.artist) = a.name;
            `);
            console.log(`✅ Canciones vinculadas desde columna artist: ${updatedFromArtist}`);
        } else {
            console.log('ℹ️ Columna "artist" no presente o ya migrada.');
        }

        // 3. Asignar autor por defecto a cualquier canción que aún tenga authorId NULL
        const remainingNulls = await prisma.$executeRawUnsafe(`
            UPDATE songs
            SET "authorId" = ${defaultAuthorId}
            WHERE "authorId" IS NULL;
        `);
        if (remainingNulls > 0) {
            console.log(`ℹ️ Asignado autor "Desconocido" a ${remainingNulls} canciones sin autor.`);
        }

        const totalAuthors = await prisma.author.count();
        const totalSongs = await prisma.song.count();
        console.log(`🎉 Migración finalizada con éxito. Autores en base de datos: ${totalAuthors}, Canciones: ${totalSongs}.`);
    } catch (error) {
        console.error('❌ Error durante la migración de autores:', error.message);
    } finally {
        await prisma.$disconnect();
    }
}

if (require.main === module) {
    migrateArtistsToAuthors();
}

module.exports = migrateArtistsToAuthors;


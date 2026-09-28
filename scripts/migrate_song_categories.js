const prisma = require('../prismaClient');

async function migrate() {
    console.log('--- Migrating Song Categories to Many-to-Many ---');
    try {
        // Query current songs with categoryId
        const songsWithCategory = await prisma.song.findMany({
            where: {
                categoryId: {
                    not: null
                }
            },
            select: {
                id: true,
                categoryId: true,
                title: true
            }
        });

        console.log(`Found ${songsWithCategory.length} songs with a categoryId.`);

        let migratedCount = 0;
        for (const song of songsWithCategory) {
            // Check if already connected in _CategoryToSong
            const updated = await prisma.song.update({
                where: { id: song.id },
                data: {
                    categories: {
                        connect: { id: song.categoryId }
                    }
                },
                include: {
                    categories: true
                }
            });
            console.log(`Song "${song.title}" (ID: ${song.id}) connected to categories: ${updated.categories.map(c => c.name).join(', ')}`);
            migratedCount++;
        }

        console.log(`✅ Successfully migrated ${migratedCount} songs to many-to-many categories.`);
    } catch (error) {
        console.error('❌ Migration failed:', error);
        process.exit(1);
    } finally {
        await prisma.$disconnect();
    }
}

migrate();

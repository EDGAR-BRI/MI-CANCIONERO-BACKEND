const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

async function cleanAndSeedCategories() {
    console.log('Merging duplicate categories and adding liturgical categories...');

    // Connect songs from 3 to 1
    const songsIn3 = await prisma.song.findMany({ where: { categories: { some: { id: 3 } } } });
    for (const s of songsIn3) {
        await prisma.song.update({
            where: { id: s.id },
            data: {
                categories: {
                    connect: { id: 1 },
                    disconnect: { id: 3 }
                }
            }
        });
    }

    // Connect songs from 4 to 2
    const songsIn4 = await prisma.song.findMany({ where: { categories: { some: { id: 4 } } } });
    for (const s of songsIn4) {
        await prisma.song.update({
            where: { id: s.id },
            data: {
                categories: {
                    connect: { id: 2 },
                    disconnect: { id: 4 }
                }
            }
        });
    }

    // Delete redundant categories 3 and 4
    await prisma.category.deleteMany({ where: { id: { in: [3, 4] } } });

    // Seed standard liturgical categories if not existing
    const standardCategories = [
        'Entrada',
        'Piedad / Perdón',
        'Gloria',
        'Aleluya / Aclamación',
        'Ofertorio',
        'Santo',
        'Paz / Cordero',
        'Comunión',
        'Meditación',
        'Salida',
        'Mariano',
        'Cuaresma',
        'Pascua',
        'Navidad'
    ];

    const existing = await prisma.category.findMany();
    const existingNames = new Set(existing.map(c => c.name.toLowerCase().trim()));

    for (const name of standardCategories) {
        if (!existingNames.has(name.toLowerCase().trim())) {
            await prisma.category.create({ data: { name } });
            console.log(`Created category: ${name}`);
        }
    }

    await cache.delPattern('songs:*');
    await cache.del('stats');
    console.log('Categories cleaned, seeded and cache cleared successfully!');
}

cleanAndSeedCategories()
    .then(() => prisma.$disconnect())
    .catch(err => {
        console.error(err);
        prisma.$disconnect();
    });

const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');

async function main() {
    console.log('Start seeding ...');

    // Permissions
    const permissions = [
        'view.admin',        // Access to Admin Panel
        'user.manage',       // Create/Edit/Delete Users
        'song.create',       // Create new songs
        'song.edit',         // Edit existing songs
        'song.delete',       // Delete songs
        'misa.create',       // Create new Misas
        // 'misa.view' is public, so no permission needed strictly, or handled by auth
    ];

    const permissionRecords = {};
    for (const perm of permissions) {
        permissionRecords[perm] = await prisma.permission.upsert({
            where: { name: perm },
            update: {},
            create: { name: perm },
        });
    }

    console.log('Permissions created.');

    // Roles
    const adminRole = await prisma.role.upsert({
        where: { id: 1 },
        update: {
            permissions: {
                set: [], // Clear existing to ensure clean slate on re-seed
                connect: permissions.map(p => ({ name: p }))
            }
        },
        create: {
            name: 'ADMIN',
            permissions: {
                connect: permissions.map(p => ({ name: p }))
            }
        },
    });

    // User Role (Usuario normal)
    const userRole = await prisma.role.upsert({
        where: { id: 2 },
        update: {
            name: 'USER',
            permissions: {
                set: [],
                connect: [{ name: 'misa.create' }]
            }
        },
        create: {
            name: 'USER',
            permissions: {
                connect: [{ name: 'misa.create' }]
            }
        },
    });

    // Musico Role (Músico: puede crear y editar canciones y crear misas)
    const musicoPermissions = ['song.create', 'song.edit', 'misa.create'];
    const musicoRole = await prisma.role.upsert({
        where: { id: 3 },
        update: {
            name: 'MUSICO',
            permissions: {
                set: [],
                connect: musicoPermissions.map(p => ({ name: p }))
            }
        },
        create: {
            name: 'MUSICO',
            permissions: {
                connect: musicoPermissions.map(p => ({ name: p }))
            }
        },
    });

    console.log('Roles created (ADMIN, USER, MUSICO).');

    // Categories
    const catAdoracion = await prisma.category.create({
        data: { name: 'Adoración' },
    });

    const catAlabanza = await prisma.category.create({
        data: { name: 'Alabanza' },
    });

    console.log('Categories created.');

    // Moments
    const moments = ["Entrada", "Piedad", "Gloria", "Aleluya", "Ofertorio", "Santo", "Cordero", "Comunión", "Salida"];

    for (const moment of moments) {
        await prisma.moment.upsert({
            where: { nombre: moment },
            update: {},
            create: { nombre: moment },
        });
    }

    console.log('Moments created.');

    // User
    const hashedPassword = await bcrypt.hash('password123', 10);
    const adminUser = await prisma.user.upsert({
        where: { email: 'admin@admin.com' },
        update: {
            password: hashedPassword // Update password even if user exists to ensure hash
        },
        create: {
            email: 'admin@admin.com',
            name: 'Admin User',
            password: hashedPassword,
            roleId: adminRole.id,
        },
    });

    console.log('Admin user created.');

    // Authors
    const authorDesconocido = await prisma.author.upsert({
        where: { name: 'Desconocido' },
        update: {},
        create: { name: 'Desconocido' },
    });

    const authorMarcosWitt = await prisma.author.upsert({
        where: { name: 'Marcos Witt' },
        update: {},
        create: { name: 'Marcos Witt' },
    });

    const authorPalabraEnAccion = await prisma.author.upsert({
        where: { name: 'Palabra en Acción' },
        update: {},
        create: { name: 'Palabra en Acción' },
    });

    console.log('Authors created.');

    // Songs
    await prisma.song.create({
        data: {
            title: 'Tu Fidelidad',
            authorId: authorMarcosWitt.id,
            content: 'Tu fid[C]elidad es grande...',
            key: 'D',
            categories: {
                connect: [{ id: catAdoracion.id }, { id: catAlabanza.id }],
            },
        },
    });

    await prisma.song.create({
        data: {
            title: 'Renuévame',
            authorId: authorMarcosWitt.id,
            content: 'Renuéva[Dm]me, Señor Jesús...',
            key: 'D',
            categories: {
                connect: [{ id: catAdoracion.id }],
            },
        },
    });

    await prisma.song.create({
        data: {
            title: 'Cantaré al Señor por siempre',
            authorId: authorPalabraEnAccion.id,
            content: 'Cant[Em]aré al Señor por siempre, su diestra es todo poder...',
            key: 'Em',
            categories: {
                connect: [{ id: catAlabanza.id }],
            },
        },
    });

    console.log('Songs created.');
    console.log('Seeding finished.');
}

main()
    .then(async () => {
        await prisma.$disconnect();
    })
    .catch(async (e) => {
        console.error(e);
        await prisma.$disconnect();
        process.exit(1);
    });

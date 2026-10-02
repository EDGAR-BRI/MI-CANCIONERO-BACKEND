const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

exports.getAllCategories = async (req, res) => {
    try {
        const isAdmin = req.user?.role === 'ADMIN';
        const where = isAdmin ? {} : { isSecret: false };

        const categories = await prisma.category.findMany({
            where,
            include: {
                _count: {
                    select: { songs: true }
                }
            },
            orderBy: { name: 'asc' }
        });
        res.json(categories);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.createCategory = async (req, res) => {
    const { name, isSecret } = req.body;
    try {
        if (!name || !name.trim()) {
            return res.status(400).json({ error: 'El nombre de la categoría es requerido' });
        }

        const category = await prisma.category.create({
            data: {
                name: name.trim(),
                isSecret: isSecret === true || isSecret === 'true',
            },
            include: {
                _count: {
                    select: { songs: true }
                }
            }
        });
        await cache.del('stats');
        await cache.delPattern('songs:*');
        res.status(201).json(category);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.updateCategory = async (req, res) => {
    const { id } = req.params;
    const { name, isSecret } = req.body;
    try {
        const data = {};
        if (name !== undefined) data.name = name.trim();
        if (isSecret !== undefined) data.isSecret = isSecret === true || isSecret === 'true';

        const category = await prisma.category.update({
            where: { id: parseInt(id) },
            data,
            include: {
                _count: {
                    select: { songs: true }
                }
            }
        });
        await cache.del('stats');
        await cache.delPattern('songs:*');
        res.json(category);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.deleteCategory = async (req, res) => {
    const { id } = req.params;
    try {
        const categoryId = parseInt(id);
        const songCount = await prisma.song.count({
            where: {
                categories: {
                    some: { id: categoryId }
                }
            }
        });

        if (songCount > 0) {
            return res.status(400).json({
                error: `No se puede eliminar la categoría porque tiene ${songCount} canción(es) asociada(s).`
            });
        }

        await prisma.category.delete({
            where: { id: categoryId }
        });
        await cache.del('stats');
        await cache.delPattern('songs:*');
        res.json({ message: 'Categoría eliminada correctamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

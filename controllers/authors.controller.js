const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

const AUTHORS_LIST_TTL = 3600; // 1 hour

exports.getAllAuthors = async (req, res) => {
    try {
        const { q } = req.query;

        if (!q) {
            const cacheKey = 'authors:list:all';
            const cached = await cache.get(cacheKey);
            if (cached) return res.json(cached);

            const authors = await prisma.author.findMany({
                orderBy: { name: 'asc' },
                include: {
                    _count: {
                        select: { songs: true }
                    }
                }
            });

            await cache.set(cacheKey, authors, AUTHORS_LIST_TTL);
            return res.json(authors);
        }

        const authors = await prisma.author.findMany({
            where: {
                name: {
                    contains: q,
                    mode: 'insensitive'
                }
            },
            orderBy: { name: 'asc' },
            include: {
                _count: {
                    select: { songs: true }
                }
            }
        });

        res.json(authors);
    } catch (error) {
        console.error('Error fetching authors:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.getAuthorById = async (req, res) => {
    const { id } = req.params;
    try {
        const author = await prisma.author.findUnique({
            where: { id: parseInt(id) },
            include: {
                songs: {
                    include: { categories: true }
                },
                _count: {
                    select: { songs: true }
                }
            }
        });

        if (!author) {
            return res.status(404).json({ error: 'Autor no encontrado' });
        }

        res.json(author);
    } catch (error) {
        console.error('Error fetching author by ID:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.createAuthor = async (req, res) => {
    const { name } = req.body;
    if (!name || !name.trim()) {
        return res.status(400).json({ error: 'El nombre del autor es obligatorio' });
    }

    const trimmedName = name.trim();

    try {
        // Verificar si ya existe con el mismo nombre (case insensitive)
        const existing = await prisma.author.findFirst({
            where: {
                name: {
                    equals: trimmedName,
                    mode: 'insensitive'
                }
            }
        });

        if (existing) {
            return res.status(200).json(existing);
        }

        const author = await prisma.author.create({
            data: { name: trimmedName }
        });

        await cache.delPattern('authors:*');
        res.status(201).json(author);
    } catch (error) {
        console.error('Error creating author:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.updateAuthor = async (req, res) => {
    const { id } = req.params;
    const { name } = req.body;

    if (!name || !name.trim()) {
        return res.status(400).json({ error: 'El nombre del autor es obligatorio' });
    }

    try {
        const updated = await prisma.author.update({
            where: { id: parseInt(id) },
            data: { name: name.trim() }
        });

        await cache.delPattern('authors:*');
        await cache.delPattern('songs:*');
        res.json(updated);
    } catch (error) {
        console.error('Error updating author:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.deleteAuthor = async (req, res) => {
    const { id } = req.params;
    const authorId = parseInt(id);

    try {
        // Verificar autor
        const author = await prisma.author.findUnique({
            where: { id: authorId },
            include: { _count: { select: { songs: true } } }
        });

        if (!author) {
            return res.status(404).json({ error: 'Autor no encontrado' });
        }

        if (author.name.toLowerCase() === 'desconocido') {
            return res.status(400).json({ error: 'No se puede eliminar el autor por defecto "Desconocido"' });
        }

        if (author._count.songs > 0) {
            // Reasignar canciones al autor por defecto "Desconocido"
            let defaultAuthor = await prisma.author.findUnique({ where: { name: 'Desconocido' } });
            if (!defaultAuthor) {
                defaultAuthor = await prisma.author.create({ data: { name: 'Desconocido' } });
            }

            await prisma.song.updateMany({
                where: { authorId },
                data: { authorId: defaultAuthor.id }
            });
        }

        await prisma.author.delete({
            where: { id: authorId }
        });

        await cache.delPattern('authors:*');
        await cache.delPattern('songs:*');
        res.json({ message: 'Autor eliminado correctamente' });
    } catch (error) {
        console.error('Error deleting author:', error);
        res.status(500).json({ error: error.message });
    }
};

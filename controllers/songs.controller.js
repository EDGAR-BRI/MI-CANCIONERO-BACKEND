const prisma = require('../prismaClient');
const cache = require('../services/cache.service');

const SONGS_LIST_TTL = 3600; // 1 hour
const SONG_DETAIL_TTL = 900; // 15 minutes

const formatSong = (song) => {
    if (!song) return song;
    const categories = song.categories || [];
    return {
        ...song,
        category: categories[0] || null,
        categoryId: categories[0]?.id || song.categoryId || null,
        author: song.author || null,
        authorId: song.authorId || song.author?.id || null,
    };
};

const resolveAuthorId = async (authorId, authorName) => {
    if (authorId !== undefined && authorId !== null && authorId !== '') {
        const parsed = parseInt(authorId);
        if (!isNaN(parsed)) return parsed;
    }

    if (authorName && typeof authorName === 'string' && authorName.trim()) {
        const trimmed = authorName.trim();
        let author = await prisma.author.findFirst({
            where: {
                name: {
                    equals: trimmed,
                    mode: 'insensitive'
                }
            }
        });

        if (!author) {
            author = await prisma.author.create({
                data: { name: trimmed }
            });
            await cache.delPattern('authors:*');
        }

        return author.id;
    }

    // Default: 'Desconocido'
    let defaultAuthor = await prisma.author.findUnique({
        where: { name: 'Desconocido' }
    });

    if (!defaultAuthor) {
        defaultAuthor = await prisma.author.create({
            data: { name: 'Desconocido' }
        });
        await cache.delPattern('authors:*');
    }

    return defaultAuthor.id;
};

exports.getAllSongs = async (req, res) => {
    try {
        const { q, categoryId, categoryIds, authorId, limit } = req.query;
        const where = {};

        if (categoryIds) {
            const ids = Array.isArray(categoryIds)
                ? categoryIds.map(Number)
                : String(categoryIds).split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
            if (ids.length > 0) {
                where.categories = { some: { id: { in: ids } } };
            }
        } else if (categoryId) {
            where.categories = { some: { id: parseInt(categoryId) } };
        }

        if (authorId) {
            const parsedAuthorId = parseInt(authorId);
            if (!isNaN(parsedAuthorId)) {
                where.authorId = parsedAuthorId;
            }
        }

        // Default: Show only active songs unless user is ADMIN and specifies active filter
        const isAdmin = req.user?.role === 'ADMIN';
        let activeFilter = true;

        if (isAdmin) {
            if (req.query.active === 'false') {
                activeFilter = false;
            } else if (req.query.active === 'all') {
                activeFilter = undefined;
            }
        }

        if (activeFilter !== undefined) {
            where.active = activeFilter;
        }

        const queryOptions = {
            where,
            orderBy: { id: 'desc' }
        };

        const catCacheTag = categoryIds ? `cats:${Array.isArray(categoryIds) ? categoryIds.join(',') : categoryIds}` : (categoryId || 'all');
        const authorCacheTag = authorId || 'all';

        if (!q) {
            const cacheKey = `songs:list:${catCacheTag}:${authorCacheTag}:${activeFilter}`;
            const cached = await cache.get(cacheKey);
            if (cached) return res.json(cached);

            queryOptions.select = {
                id: true,
                title: true,
                key: true,
                url_song: true,
                active: true,
                categoryId: true,
                categories: true,
                authorId: true,
                author: true,
                user: { select: { name: true } }
            };
        } else {
            queryOptions.include = { categories: true, author: true, user: { select: { name: true } } };
        }

        if (!q && limit) {
            queryOptions.take = parseInt(limit);
        }

        const rawSongs = await prisma.song.findMany(queryOptions);
        const songs = rawSongs.map(formatSong);

        if (!q) {
            const cacheKey = `songs:list:${catCacheTag}:${authorCacheTag}:${activeFilter}`;
            await cache.set(cacheKey, songs, SONGS_LIST_TTL);
            return res.json(songs);
        }

        const normalize = (str) => {
            return str
                ? str.normalize("NFD").replace(/[\u0300-\u036f]/g, "").toLowerCase()
                : "";
        };

        const stripChords = (str) => {
            return str ? str.replace(/\[.*?\]/g, "") : "";
        };

        const search = normalize(q);

        const filteredSongs = songs.filter((song) => {
            const cleanContent = stripChords(song.content);
            const authorName = song.author?.name || '';
            return (
                normalize(song.title).includes(search) ||
                normalize(authorName).includes(search) ||
                normalize(cleanContent).includes(search)
            );
        });

        res.json(filteredSongs);
    } catch (error) {
        console.error('Error in getAllSongs:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.createSong = async (req, res) => {
    const { title, authorId, authorName, content, key, url_song, categoryId, categoryIds } = req.body;
    try {
        let targetCategoryIds = [];
        if (Array.isArray(categoryIds)) {
            targetCategoryIds = categoryIds.map(id => parseInt(id)).filter(id => !isNaN(id));
        } else if (categoryIds) {
            targetCategoryIds = String(categoryIds).split(',').map(id => parseInt(id.trim())).filter(id => !isNaN(id));
        } else if (categoryId !== undefined && categoryId !== null && categoryId !== '') {
            const parsed = parseInt(categoryId);
            if (!isNaN(parsed)) targetCategoryIds = [parsed];
        }

        const targetAuthorId = await resolveAuthorId(authorId, authorName);

        const createData = {
            title,
            content,
            key,
            url_song,
            authorId: targetAuthorId,
            categoryId: targetCategoryIds[0] || null,
            active: true,
            userId: req.user ? req.user.id : null,
        };

        if (targetCategoryIds.length > 0) {
            createData.categories = {
                connect: targetCategoryIds.map(id => ({ id }))
            };
        }

        const song = await prisma.song.create({
            data: createData,
            include: { categories: true, author: true, user: { select: { name: true } } }
        });

        await cache.delPattern('songs:list:*');
        await cache.delPattern('authors:*');
        await cache.del('stats');
        res.json(formatSong(song));
    } catch (error) {
        console.error('Error in createSong:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.getSongById = async (req, res) => {
    const { id } = req.params;
    try {
        const cacheKey = `songs:detail:${id}`;
        const cached = await cache.get(cacheKey);
        if (cached) return res.json(cached);

        const song = await prisma.song.findUnique({
            where: { id: parseInt(id) },
            include: { categories: true, author: true, user: { select: { name: true } } },
        });
        if (!song) return res.status(404).json({ error: 'Song not found' });

        const formatted = formatSong(song);
        await cache.set(cacheKey, formatted, SONG_DETAIL_TTL);
        res.json(formatted);
    } catch (error) {
        console.error('Error in getSongById:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.updateSong = async (req, res) => {
    const { id } = req.params;
    const { title, authorId, authorName, content, key, url_song, categoryId, categoryIds, active } = req.body;
    try {
        const data = {};
        if (title !== undefined) data.title = title;
        if (content !== undefined) data.content = content;
        if (key !== undefined) data.key = key;
        if (url_song !== undefined) data.url_song = url_song;
        if (active !== undefined) data.active = active;

        if (authorId !== undefined || authorName !== undefined) {
            data.authorId = await resolveAuthorId(authorId, authorName);
        }

        let targetCategoryIds = null;
        if (Array.isArray(categoryIds)) {
            targetCategoryIds = categoryIds.map(val => parseInt(val)).filter(val => !isNaN(val));
        } else if (typeof categoryIds === 'string' && categoryIds.trim() !== '') {
            targetCategoryIds = categoryIds.split(',').map(s => parseInt(s.trim())).filter(n => !isNaN(n));
        } else if (categoryId !== undefined && categoryId !== null && categoryId !== '') {
            const parsed = parseInt(categoryId);
            if (!isNaN(parsed)) targetCategoryIds = [parsed];
        }

        if (targetCategoryIds !== null) {
            data.categories = {
                set: targetCategoryIds.map(catId => ({ id: catId }))
            };
            data.categoryId = targetCategoryIds[0] || null;
        }

        const song = await prisma.song.update({
            where: { id: parseInt(id) },
            data,
            include: { categories: true, author: true, user: { select: { name: true } } }
        });

        await cache.delPattern('songs:list:*');
        await cache.del(`songs:detail:${id}`);
        await cache.delPattern('authors:*');
        await cache.del('stats');
        res.json(formatSong(song));
    } catch (error) {
        console.error('Error in updateSong:', error);
        res.status(500).json({ error: error.message });
    }
};

exports.deleteSong = async (req, res) => {
    const { id } = req.params;
    try {
        await prisma.song.delete({
            where: { id: parseInt(id) },
        });
        await cache.delPattern('songs:list:*');
        await cache.del(`songs:detail:${id}`);
        await cache.delPattern('authors:*');
        await cache.del('stats');
        res.json({ message: 'Song deleted successfully' });
    } catch (error) {
        console.error('Error in deleteSong:', error);
        res.status(500).json({ error: error.message });
    }
};

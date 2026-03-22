const prisma = require('../prismaClient');

const getUserId = (req) => {
    return req.user?.id || null;
};

exports.getAllMisas = async (req, res) => {
    const userId = getUserId(req);
    try {
        const whereClause = {
            OR: [
                { visibility: 'PUBLIC' }
            ]
        };

        if (userId) {
            whereClause.OR.push({ userId: userId });
        }

        const misas = await prisma.misa.findMany({
            where: whereClause,
            include: {
                misaSongs: {
                    include: {
                        song: true,
                        moment: true
                    }
                },
                user: { select: { name: true } }
            },
            orderBy: { dateMisa: 'desc' }
        });
        const misasWithOwnership = misas.map((misa) => ({
            ...misa,
            isOwner: Boolean(userId && misa.userId === userId)
        }));
        res.json(misasWithOwnership);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.getMisaById = async (req, res) => {
    const { id } = req.params;
    const { share_token: shareToken, edit_token: editToken } = req.query;
    const userId = getUserId(req);

    try {
        const misa = await prisma.misa.findUnique({
            where: { id: parseInt(id) },
            include: {
                misaSongs: {
                    include: {
                        song: true,
                        moment: true
                    },
                    orderBy: { id: 'asc' }
                },
                user: { select: { name: true } }
            }
        });

        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const isOwner = userId && misa.userId === userId;
        const isPublic = misa.visibility === 'PUBLIC';
        const hasValidShareToken = shareToken && shareToken === misa.shareToken;
        const hasValidEditToken = editToken && editToken === misa.editToken;

        const canEdit = isOwner || hasValidEditToken;

        // Access control:
        // Public -> Everyone can view
        // Private -> Owner, EditToken, or ShareToken required to view
        // RELAXED: User requested that knowing the ID (link) should be enough to view (Unlisted behavior)
        /*
        if (!isPublic && !canEdit && !hasValidShareToken) {
            return res.status(403).json({ error: 'Access denied' });
        }
        */

        res.json({ ...misa, isOwner, canEdit });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.createMisa = async (req, res) => {
    const { title, dateMisa, visibility } = req.body;
    // req.user is set by middleware
    const userId = req.user ? req.user.id : null;

    try {
        const misa = await prisma.misa.create({
            data: {
                title,
                dateMisa: new Date(dateMisa),
                visibility: visibility || "PUBLIC",
                userId: userId
            },
        });
        res.json(misa);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.updateMisa = async (req, res) => {
    const { id } = req.params;
    const { title, dateMisa, visibility } = req.body;
    const { edit_token: editToken } = req.query;
    const userId = req.user ? req.user.id : null;

    try {
        // Check ownership
        const existingMisa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!existingMisa) return res.status(404).json({ error: 'Misa not found' });

        const isOwner = existingMisa.userId && existingMisa.userId === userId;
        const hasValidEditToken = editToken && editToken === existingMisa.editToken;

        if (!isOwner && !hasValidEditToken) {
            return res.status(403).json({ error: 'Not authorized to update this misa' });
        }

        const misa = await prisma.misa.update({
            where: { id: parseInt(id) },
            data: {
                title,
                dateMisa: dateMisa ? new Date(dateMisa) : undefined,
                visibility
            },
        });
        res.json(misa);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.deleteMisa = async (req, res) => {
    const { id } = req.params;
    const userId = req.user ? req.user.id : null;

    try {
        // Check ownership
        const existingMisa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!existingMisa) return res.status(404).json({ error: 'Misa not found' });

        if (existingMisa.userId && existingMisa.userId !== userId) {
            return res.status(403).json({ error: 'Not authorized to delete this misa' });
        }

        await prisma.misa.delete({
            where: { id: parseInt(id) },
        });
        res.json({ message: 'Misa deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// MisaSong Management
exports.addSongToMisa = async (req, res) => {
    const { id } = req.params; // Misa ID
    const { songId, momentId, key } = req.body;
    const { edit_token: editToken } = req.query;
    const userId = req.user ? req.user.id : null;

    try {
        // Check ownership of Misa
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const isOwner = misa.userId && misa.userId === userId;
        const hasValidEditToken = editToken && editToken === misa.editToken;

        if (!isOwner && !hasValidEditToken) {
            return res.status(403).json({ error: 'Not authorized to add songs to this misa' });
        }

        const misaSong = await prisma.misaSong.create({
            data: {
                misaId: parseInt(id),
                songId: parseInt(songId),
                momentId: momentId ? parseInt(momentId) : null,
                key: key || null
            },
            include: { song: true, moment: true }
        });
        res.json(misaSong);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.removeSongFromMisa = async (req, res) => {
    const { id, misaSongId } = req.params;
    const { edit_token: editToken } = req.query;
    const userId = req.user ? req.user.id : null;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const isOwner = misa.userId && misa.userId === userId;
        const hasValidEditToken = editToken && editToken === misa.editToken;

        if (!isOwner && !hasValidEditToken) {
            return res.status(403).json({ error: 'Not authorized to remove songs from this misa' });
        }
        await prisma.misaSong.delete({
            where: { id: parseInt(misaSongId) }
        });
        res.json({ message: 'Song removed from misa' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

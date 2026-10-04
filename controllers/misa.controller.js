const prisma = require('../prismaClient');
const cache = require('../services/cache.service');
const { generateMisaPdf } = require('../services/pdf.service');

const MISAS_LIST_TTL = 3600; // 1 hour

const getUserId = (req) => {
    return req.user?.id || null;
};

const canUserEditMisa = async (misa, userOrId) => {
    if (!misa || !userOrId) return false;
    const userId = typeof userOrId === 'object' ? userOrId.id : userOrId;
    const userRole = typeof userOrId === 'object' ? userOrId.role : null;

    if (userRole === 'ADMIN') return true;
    if (misa.userId && userId === misa.userId) return true;

    if (misa.ministryId && userId) {
        const member = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: misa.ministryId,
                    userId: userId
                }
            }
        });
        if (member && member.status === 'ACTIVE') {
            return true;
        }
    }
    return false;
};

exports.getAllMisas = async (req, res) => {
    const userId = getUserId(req);
    try {
        if (!userId) {
            const cached = await cache.get('misas:public');
            if (cached) return res.json(cached);
        }

        const whereClause = {
            OR: [
                { visibility: 'PUBLIC' }
            ]
        };

        if (userId) {
            whereClause.OR.push(
                { userId: userId },
                { ministry: { members: { some: { userId: userId, status: 'ACTIVE' } } } }
            );
        }

        const misas = await prisma.misa.findMany({
            where: whereClause,
            include: {
                misaMoments: {
                    include: { moment: true },
                    orderBy: { order: 'asc' }
                },
                misaSongs: {
                    include: {
                        song: true,
                        moment: true
                    },
                    orderBy: [
                        { order: 'asc' },
                        { id: 'asc' }
                    ]
                },
                user: { select: { id: true, name: true } },
                ministry: {
                    select: {
                        id: true,
                        name: true,
                        avatarUrl: true
                    }
                }
            },
            orderBy: { dateMisa: 'desc' }
        });
        const misasWithOwnership = misas.map((misa) => ({
            ...misa,
            isOwner: Boolean(userId && misa.userId === userId)
        }));

        if (!userId) {
            await cache.set('misas:public', misasWithOwnership, MISAS_LIST_TTL);
        }

        res.json(misasWithOwnership);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.getMisaById = async (req, res) => {
    const { id } = req.params;
    const user = req.user || null;
    const userId = user?.id || null;

    try {
        let misa = await prisma.misa.findUnique({
            where: { id: parseInt(id) },
            include: {
                misaMoments: {
                    include: { moment: true },
                    orderBy: { order: 'asc' }
                },
                misaSongs: {
                    include: {
                        song: true,
                        moment: true
                    },
                    orderBy: [
                        { order: 'asc' },
                        { id: 'asc' }
                    ]
                },
                user: { select: { id: true, name: true, email: true } },
                ministry: {
                    select: {
                        id: true,
                        name: true,
                        avatarUrl: true
                    }
                }
            }
        });

        if (!misa) return res.status(404).json({ error: 'Misa no encontrada' });

        // Auto-initialize default moments if this misa has none yet
        if (!misa.misaMoments || misa.misaMoments.length === 0) {
            const defaultMoments = await prisma.moment.findMany({ orderBy: { id: 'asc' } });
            if (defaultMoments.length > 0) {
                await prisma.misaMoment.createMany({
                    data: defaultMoments.map((dm, idx) => ({
                        misaId: misa.id,
                        momentId: dm.id,
                        order: idx
                    })),
                    skipDuplicates: true
                });
                misa.misaMoments = await prisma.misaMoment.findMany({
                    where: { misaId: misa.id },
                    include: { moment: true },
                    orderBy: { order: 'asc' }
                });
            }
        }

        const isOwner = Boolean(userId && misa.userId === userId);
        const canEdit = await canUserEditMisa(misa, user);

        // Opción 1: Privacidad estricta por cuenta
        // Si la misa es privada, solo pueden acceder el dueño, miembros activos de su ministerio o admin
        if (misa.visibility === 'PRIVATE' && !canEdit) {
            return res.status(403).json({
                error: misa.ministry
                    ? `Esta misa es privada del grupo "${misa.ministry.name}".`
                    : 'Esta misa es privada.',
                isPrivate: true,
                requiresAuth: !userId,
                ministryName: misa.ministry ? misa.ministry.name : null
            });
        }

        res.json({ ...misa, isOwner, canEdit });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.createMisa = async (req, res) => {
    const { title, dateMisa, visibility, ministryId } = req.body;
    const userId = req.user ? req.user.id : null;

    try {
        const misa = await prisma.misa.create({
            data: {
                title,
                dateMisa: new Date(dateMisa),
                visibility: visibility || "PUBLIC",
                userId: userId,
                ministryId: ministryId ? parseInt(ministryId) : null
            },
            include: {
                ministry: {
                    select: {
                        id: true,
                        name: true,
                        avatarUrl: true
                    }
                }
            }
        });

        // Initialize default moments for the new misa
        const defaultMoments = await prisma.moment.findMany({ orderBy: { id: 'asc' } });
        if (defaultMoments.length > 0) {
            await prisma.misaMoment.createMany({
                data: defaultMoments.map((dm, idx) => ({
                    misaId: misa.id,
                    momentId: dm.id,
                    order: idx
                }))
            });
        }

        await cache.delPattern('misas:*');
        res.status(201).json(misa);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.updateMisa = async (req, res) => {
    const { id } = req.params;
    const { title, dateMisa, visibility, ministryId } = req.body;
    const user = req.user;

    try {
        const existingMisa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!existingMisa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(existingMisa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to update this misa' });
        }

        const dataToUpdate = {
            title,
            dateMisa: dateMisa ? new Date(dateMisa) : undefined,
            visibility
        };
        if (ministryId !== undefined) {
            dataToUpdate.ministryId = ministryId ? parseInt(ministryId) : null;
        }

        const misa = await prisma.misa.update({
            where: { id: parseInt(id) },
            data: dataToUpdate,
            include: {
                ministry: {
                    select: {
                        id: true,
                        name: true,
                        avatarUrl: true
                    }
                }
            }
        });
        await cache.delPattern('misas:*');
        res.json(misa);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.deleteMisa = async (req, res) => {
    const { id } = req.params;
    const user = req.user;
    const userId = user?.id;

    try {
        const existingMisa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!existingMisa) return res.status(404).json({ error: 'Misa not found' });

        const isOwner = Boolean(userId && existingMisa.userId === userId);
        const isAdmin = user?.role === 'ADMIN';
        let isMinistryAdmin = false;
        if (existingMisa.ministryId && userId) {
            const member = await prisma.ministryMember.findUnique({
                where: {
                    ministryId_userId: {
                        ministryId: existingMisa.ministryId,
                        userId: userId
                    }
                }
            });
            if (member && member.status === 'ACTIVE' && member.role === 'ADMIN') {
                isMinistryAdmin = true;
            }
        }

        if (!isOwner && !isMinistryAdmin && !isAdmin) {
            return res.status(403).json({ error: 'Not authorized to delete this misa' });
        }

        await prisma.misa.delete({
            where: { id: parseInt(id) },
        });
        await cache.delPattern('misas:*');
        res.json({ message: 'Misa deleted successfully' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// Moments Management in Misa
exports.addMomentToMisa = async (req, res) => {
    const { id } = req.params;
    const { momentId, name } = req.body;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to edit this misa' });
        }

        let targetMomentId = momentId ? parseInt(momentId) : null;

        // Custom moment name provided
        if (!targetMomentId && name && name.trim()) {
            const trimmedName = name.trim();
            let existingMoment = await prisma.moment.findFirst({
                where: { nombre: { equals: trimmedName, mode: 'insensitive' } }
            });
            if (!existingMoment) {
                existingMoment = await prisma.moment.create({
                    data: { nombre: trimmedName }
                });
            }
            targetMomentId = existingMoment.id;
        }

        if (!targetMomentId) {
            return res.status(400).json({ error: 'Se requiere momentId o un nombre válido' });
        }

        // Check if already in misa
        const existingLink = await prisma.misaMoment.findUnique({
            where: {
                misaId_momentId: {
                    misaId: parseInt(id),
                    momentId: targetMomentId
                }
            },
            include: { moment: true }
        });

        if (existingLink) {
            return res.json(existingLink);
        }

        const maxOrderMoment = await prisma.misaMoment.findFirst({
            where: { misaId: parseInt(id) },
            orderBy: { order: 'desc' }
        });
        const nextOrder = maxOrderMoment ? maxOrderMoment.order + 1 : 0;

        const newMisaMoment = await prisma.misaMoment.create({
            data: {
                misaId: parseInt(id),
                momentId: targetMomentId,
                order: nextOrder
            },
            include: { moment: true }
        });

        await cache.delPattern('misas:*');
        res.status(201).json(newMisaMoment);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.removeMomentFromMisa = async (req, res) => {
    const { id, momentId } = req.params;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to edit this misa' });
        }

        const mid = parseInt(id);
        const momId = parseInt(momentId);

        await prisma.misaMoment.deleteMany({
            where: {
                misaId: mid,
                momentId: momId
            }
        });

        await prisma.misaSong.deleteMany({
            where: {
                misaId: mid,
                momentId: momId
            }
        });

        await cache.delPattern('misas:*');
        res.json({ message: 'Momento eliminado de la misa' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.reorderMoments = async (req, res) => {
    const { id } = req.params;
    const { orderedMomentIds } = req.body;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to edit this misa' });
        }

        if (!Array.isArray(orderedMomentIds)) {
            return res.status(400).json({ error: 'orderedMomentIds must be an array' });
        }

        const mid = parseInt(id);
        const updates = orderedMomentIds.map((momId, idx) =>
            prisma.misaMoment.updateMany({
                where: { misaId: mid, momentId: parseInt(momId) },
                data: { order: idx }
            })
        );
        await prisma.$transaction(updates);

        await cache.delPattern('misas:*');
        res.json({ message: 'Momentos reordenados exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

// MisaSong Management & Reordering (Drag and Drop)
exports.reorderSongs = async (req, res) => {
    const { id } = req.params;
    const { orderedSongIds, momentId } = req.body;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to edit this misa' });
        }

        if (!Array.isArray(orderedSongIds)) {
            return res.status(400).json({ error: 'orderedSongIds must be an array' });
        }

        const mid = parseInt(id);
        const updates = orderedSongIds.map((misaSongId, idx) => {
            const data = { order: idx };
            if (momentId) {
                data.momentId = parseInt(momentId);
            }
            return prisma.misaSong.updateMany({
                where: { id: parseInt(misaSongId), misaId: mid },
                data
            });
        });
        await prisma.$transaction(updates);

        await cache.delPattern('misas:*');
        res.json({ message: 'Cantos reordenados exitosamente' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.addSongToMisa = async (req, res) => {
    const { id } = req.params;
    const { songId, momentId, key } = req.body;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to add songs to this misa' });
        }

        const targetMomentId = momentId ? parseInt(momentId) : null;

        // Auto-add moment to misa if not linked yet
        if (targetMomentId) {
            const momentInMisa = await prisma.misaMoment.findUnique({
                where: {
                    misaId_momentId: {
                        misaId: parseInt(id),
                        momentId: targetMomentId
                    }
                }
            });
            if (!momentInMisa) {
                const maxOrderMoment = await prisma.misaMoment.findFirst({
                    where: { misaId: parseInt(id) },
                    orderBy: { order: 'desc' }
                });
                const nextMomOrder = maxOrderMoment ? maxOrderMoment.order + 1 : 0;
                await prisma.misaMoment.create({
                    data: {
                        misaId: parseInt(id),
                        momentId: targetMomentId,
                        order: nextMomOrder
                    }
                });
            }
        }

        const maxOrderSong = await prisma.misaSong.findFirst({
            where: {
                misaId: parseInt(id),
                momentId: targetMomentId
            },
            orderBy: { order: 'desc' }
        });
        const nextOrder = maxOrderSong ? maxOrderSong.order + 1 : 0;

        const misaSong = await prisma.misaSong.create({
            data: {
                misaId: parseInt(id),
                songId: parseInt(songId),
                momentId: targetMomentId,
                key: key || null,
                order: nextOrder
            },
            include: { song: true, moment: true }
        });
        await cache.delPattern('misas:*');
        res.status(201).json(misaSong);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.updateMisaSong = async (req, res) => {
    const { id, misaSongId } = req.params;
    const { key, momentId } = req.body;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to update songs in this misa' });
        }

        const updateData = {};
        if (key !== undefined) updateData.key = key;
        if (momentId !== undefined) updateData.momentId = momentId ? parseInt(momentId) : null;

        const updatedSong = await prisma.misaSong.update({
            where: { id: parseInt(misaSongId) },
            data: updateData,
            include: { song: true, moment: true }
        });

        await cache.delPattern('misas:*');
        res.json(updatedSong);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.removeSongFromMisa = async (req, res) => {
    const { id, misaSongId } = req.params;
    const user = req.user;

    try {
        const misa = await prisma.misa.findUnique({ where: { id: parseInt(id) } });
        if (!misa) return res.status(404).json({ error: 'Misa not found' });

        const canEdit = await canUserEditMisa(misa, user);
        if (!canEdit) {
            return res.status(403).json({ error: 'Not authorized to remove songs from this misa' });
        }

        await prisma.misaSong.delete({
            where: { id: parseInt(misaSongId) }
        });
        await cache.delPattern('misas:*');
        res.json({ message: 'Song removed from misa' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
};

exports.exportMisaPdf = async (req, res) => {
    const { id } = req.params;
    const user = req.user || null;
    const withChords = req.query.chords !== 'false';
    const isDownload = req.query.download !== 'false';

    try {
        const misaId = parseInt(id);
        if (isNaN(misaId)) {
            return res.status(400).json({ error: 'ID de misa inválido' });
        }

        // 1. Cache lookup
        const cacheKey = `misas:pdf:${misaId}:${withChords ? 'chords' : 'lyrics'}`;
        const cached = await cache.get(cacheKey);

        if (cached && cached.base64) {
            const buffer = Buffer.from(cached.base64, 'base64');
            const disposition = isDownload ? 'attachment' : 'inline';
            const filename = cached.filename || `Misa_${misaId}_${withChords ? 'acordes' : 'letra'}.pdf`;
            res.setHeader('Content-Type', 'application/pdf');
            res.setHeader('Content-Disposition', `${disposition}; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
            res.setHeader('X-Cache', 'HIT');
            return res.send(buffer);
        }

        // 2. Fetch Misa with all relations from database
        const misa = await prisma.misa.findUnique({
            where: { id: misaId },
            include: {
                misaMoments: {
                    include: { moment: true },
                    orderBy: { order: 'asc' }
                },
                misaSongs: {
                    include: {
                        song: {
                            include: { author: true }
                        },
                        moment: true
                    },
                    orderBy: [
                        { order: 'asc' },
                        { id: 'asc' }
                    ]
                },
                user: { select: { id: true, name: true } },
                ministry: {
                    select: {
                        id: true,
                        name: true
                    }
                }
            }
        });

        if (!misa) {
            return res.status(404).json({ error: 'Misa no encontrada' });
        }

        // 3. Privacy permissions check
        const canEdit = await canUserEditMisa(misa, user);
        if (misa.visibility === 'PRIVATE' && !canEdit) {
            return res.status(403).json({
                error: misa.ministry
                    ? `Esta misa es privada del grupo "${misa.ministry.name}".`
                    : 'Esta misa es privada.'
            });
        }

        // 4. Generate PDF buffer
        const pdfBuffer = await generateMisaPdf(misa, { withChords });
        const rawTitle = (misa.title || 'Misa').trim();
        const hasMisaPrefix = /^misa\b/i.test(rawTitle);
        const cleanTitle = rawTitle
            .normalize('NFD')
            .replace(/[\u0300-\u036f]/g, '')
            .replace(/[^a-zA-Z0-9_\-]/g, '_')
            .replace(/_+/g, '_')
            .replace(/^_|_$/g, '');

        const baseName = hasMisaPrefix ? cleanTitle : `Misa_${cleanTitle}`;

        let datePart = '';
        if (misa.dateMisa) {
            const d = new Date(misa.dateMisa);
            if (!isNaN(d.getTime())) {
                const year = d.getFullYear();
                const month = String(d.getMonth() + 1).padStart(2, '0');
                const day = String(d.getDate()).padStart(2, '0');
                datePart = `${year}-${month}-${day}`;
            }
        }

        const suffix = withChords ? 'acordes' : 'letra';
        const filename = datePart
            ? `${baseName}_${datePart}_${suffix}.pdf`
            : `${baseName}_${suffix}.pdf`;

        // 5. Store in cache for 24 hours
        await cache.set(cacheKey, {
            base64: pdfBuffer.toString('base64'),
            filename,
            generatedAt: Date.now()
        }, 86400);

        const disposition = isDownload ? 'attachment' : 'inline';
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `${disposition}; filename="${filename}"; filename*=UTF-8''${encodeURIComponent(filename)}`);
        res.setHeader('X-Cache', 'MISS');
        return res.send(pdfBuffer);
    } catch (error) {
        console.error('Error generating Misa PDF:', error);
        res.status(500).json({ error: 'Error al generar el PDF de la misa: ' + error.message });
    }
};

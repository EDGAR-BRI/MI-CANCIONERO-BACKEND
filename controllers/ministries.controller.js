const prisma = require('../prismaClient');
const crypto = require('crypto');

// Helper: Verify if user is an active member or admin of a ministry
const getMembership = async (ministryId, userId) => {
    return prisma.ministryMember.findUnique({
        where: {
            ministryId_userId: {
                ministryId: parseInt(ministryId),
                userId: parseInt(userId)
            }
        },
        include: {
            ministry: true
        }
    });
};

// 1. Get all ministries for the current authenticated user
exports.getMyMinistries = async (req, res) => {
    try {
        const userId = req.user.id;

        const memberships = await prisma.ministryMember.findMany({
            where: {
                userId,
                status: 'ACTIVE',
                ministry: { active: true }
            },
            include: {
                ministry: {
                    include: {
                        _count: {
                            select: {
                                members: {
                                    where: { status: 'ACTIVE' }
                                }
                            }
                        }
                    }
                }
            },
            orderBy: { joinedAt: 'desc' }
        });

        // Also fetch pending requests sent by this user
        const pendingMemberships = await prisma.ministryMember.findMany({
            where: {
                userId,
                status: 'PENDING',
                ministry: { active: true }
            },
            include: {
                ministry: {
                    select: {
                        id: true,
                        name: true,
                        description: true,
                        avatarUrl: true
                    }
                }
            }
        });

        const activeMinistries = memberships.map(m => ({
            id: m.ministry.id,
            name: m.ministry.name,
            description: m.ministry.description,
            avatarUrl: m.ministry.avatarUrl,
            inviteCode: m.ministry.inviteCode,
            requireApproval: m.ministry.requireApproval,
            allowMemberInvites: m.ministry.allowMemberInvites,
            foundedAt: m.ministry.foundedAt,
            createdAt: m.ministry.createdAt,
            myRole: m.role,
            myStatus: m.status,
            memberCount: m.ministry._count.members
        }));

        res.json({
            ministries: activeMinistries,
            pendingRequests: pendingMemberships.map(p => ({
                ministryId: p.ministry.id,
                name: p.ministry.name,
                description: p.ministry.description,
                avatarUrl: p.ministry.avatarUrl,
                requestedAt: p.joinedAt
            }))
        });
    } catch (error) {
        console.error("Error in getMyMinistries:", error);
        res.status(500).json({ error: error.message });
    }
};

// 2. Create a new ministry
exports.createMinistry = async (req, res) => {
    try {
        const userId = req.user.id;
        const { name, description, avatarUrl, foundedAt, requireApproval, allowMemberInvites } = req.body;

        if (!name || !name.trim()) {
            return res.status(400).json({ error: "El nombre del ministerio es obligatorio." });
        }

        const inviteCode = crypto.randomUUID().slice(0, 8); // Clean 8-character invite code

        // Create ministry and set creator as first ADMIN
        const ministry = await prisma.ministry.create({
            data: {
                name: name.trim(),
                description: description?.trim() || null,
                avatarUrl: avatarUrl?.trim() || null,
                inviteCode,
                foundedAt: foundedAt ? new Date(foundedAt) : new Date(),
                requireApproval: Boolean(requireApproval),
                allowMemberInvites: Boolean(allowMemberInvites),
                members: {
                    create: {
                        userId,
                        role: 'ADMIN',
                        status: 'ACTIVE'
                    }
                }
            },
            include: {
                members: {
                    where: { userId },
                    include: {
                        user: {
                            select: { id: true, name: true, email: true }
                        }
                    }
                }
            }
        });

        res.status(201).json({
            ...ministry,
            myRole: 'ADMIN',
            memberCount: 1
        });
    } catch (error) {
        console.error("Error in createMinistry:", error);
        res.status(500).json({ error: error.message });
    }
};

// 3. Get ministry details by ID
exports.getMinistryById = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const isGlobalAdmin = req.user.role === 'ADMIN';

        const ministry = await prisma.ministry.findUnique({
            where: { id: parseInt(id) },
            include: {
                members: {
                    include: {
                        user: {
                            select: { id: true, name: true, email: true, phoneNumber: true }
                        }
                    },
                    orderBy: [
                        { role: 'asc' }, // ADMIN first
                        { joinedAt: 'asc' }
                    ]
                },
                misas: {
                    include: {
                        misaSongs: {
                            include: {
                                song: true,
                                moment: true
                            }
                        }
                    },
                    orderBy: { dateMisa: 'desc' }
                }
            }
        });

        if (!ministry || !ministry.active) {
            return res.status(404).json({ error: "Ministerio no encontrado." });
        }

        const myMembership = ministry.members.find(m => m.userId === userId);

        if (!myMembership && !isGlobalAdmin) {
            return res.status(403).json({ error: "No tienes permiso para ver este ministerio." });
        }

        const isGroupAdmin = myMembership?.role === 'ADMIN' || isGlobalAdmin;
        const canManageInvites = isGroupAdmin || ministry.allowMemberInvites;

        // Split active members and pending requests
        const activeMembers = ministry.members
            .filter(m => m.status === 'ACTIVE')
            .map(m => ({
                id: m.id,
                userId: m.user.id,
                name: m.user.name,
                email: m.user.email,
                phoneNumber: m.user.phoneNumber,
                role: m.role,
                joinedAt: m.joinedAt
            }));

        const pendingRequests = canManageInvites
            ? ministry.members
                .filter(m => m.status === 'PENDING')
                .map(m => ({
                    id: m.id,
                    userId: m.user.id,
                    name: m.user.name,
                    email: m.user.email,
                    phoneNumber: m.user.phoneNumber,
                    requestedAt: m.joinedAt
                }))
            : [];

        res.json({
            id: ministry.id,
            name: ministry.name,
            description: ministry.description,
            avatarUrl: ministry.avatarUrl,
            inviteCode: ministry.inviteCode,
            requireApproval: ministry.requireApproval,
            allowMemberInvites: ministry.allowMemberInvites,
            foundedAt: ministry.foundedAt,
            createdAt: ministry.createdAt,
            myRole: myMembership?.role || (isGlobalAdmin ? 'ADMIN' : 'MEMBER'),
            myStatus: myMembership?.status || 'ACTIVE',
            isGroupAdmin,
            canManageInvites,
            activeMembers,
            pendingRequests,
            misas: ministry.misas
        });
    } catch (error) {
        console.error("Error in getMinistryById:", error);
        res.status(500).json({ error: error.message });
    }
};

// 4. Update ministry basic details and settings
exports.updateMinistry = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;
        const { name, description, avatarUrl, foundedAt, requireApproval, allowMemberInvites } = req.body;

        const membership = await getMembership(id, userId);
        const isGlobalAdmin = req.user.role === 'ADMIN';

        if (!isGlobalAdmin && (!membership || membership.role !== 'ADMIN' || membership.status !== 'ACTIVE')) {
            return res.status(403).json({ error: "Solo los administradores del ministerio pueden modificar sus ajustes." });
        }

        const updateData = {};
        if (name !== undefined) updateData.name = name.trim();
        if (description !== undefined) updateData.description = description ? description.trim() : null;
        if (avatarUrl !== undefined) updateData.avatarUrl = avatarUrl ? avatarUrl.trim() : null;
        if (foundedAt !== undefined) updateData.foundedAt = foundedAt ? new Date(foundedAt) : undefined;
        if (requireApproval !== undefined) updateData.requireApproval = Boolean(requireApproval);
        if (allowMemberInvites !== undefined) updateData.allowMemberInvites = Boolean(allowMemberInvites);

        const updated = await prisma.ministry.update({
            where: { id: parseInt(id) },
            data: updateData
        });

        res.json(updated);
    } catch (error) {
        console.error("Error in updateMinistry:", error);
        res.status(500).json({ error: error.message });
    }
};

// 5. Join ministry by invite code
exports.joinByCode = async (req, res) => {
    try {
        const userId = req.user.id;
        const { code } = req.body;

        if (!code || !code.trim()) {
            return res.status(400).json({ error: "El código de invitación es obligatorio." });
        }

        const ministry = await prisma.ministry.findUnique({
            where: { inviteCode: code.trim() }
        });

        if (!ministry || !ministry.active) {
            return res.status(404).json({ error: "Código de invitación inválido o ministerio inexistente." });
        }

        const existingMembership = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: ministry.id,
                    userId
                }
            }
        });

        if (existingMembership) {
            if (existingMembership.status === 'ACTIVE') {
                return res.status(400).json({
                    error: "Ya eres miembro de este ministerio.",
                    ministryId: ministry.id
                });
            } else if (existingMembership.status === 'PENDING') {
                return res.status(400).json({
                    error: "Tu solicitud ya fue enviada y está en espera de aprobación.",
                    status: 'PENDING',
                    ministryId: ministry.id
                });
            }
        }

        const targetStatus = ministry.requireApproval ? 'PENDING' : 'ACTIVE';

        const membership = await prisma.ministryMember.create({
            data: {
                ministryId: ministry.id,
                userId,
                role: 'MEMBER',
                status: targetStatus
            }
        });

        res.status(201).json({
            message: targetStatus === 'ACTIVE'
                ? `¡Te has unido exitosamente a ${ministry.name}!`
                : `Solicitud enviada para unirte a ${ministry.name}. Un administrador revisará tu petición.`,
            ministry: {
                id: ministry.id,
                name: ministry.name,
                description: ministry.description,
                avatarUrl: ministry.avatarUrl
            },
            status: targetStatus
        });
    } catch (error) {
        console.error("Error in joinByCode:", error);
        res.status(500).json({ error: error.message });
    }
};

// 6. Search registered users to add directly
exports.searchUsers = async (req, res) => {
    try {
        const { id } = req.params;
        const { q } = req.query;

        if (!q || q.trim().length < 2) {
            return res.json([]);
        }

        const query = q.trim();

        // Find users matching query who are NOT already members of this ministry
        const existingMemberIds = (await prisma.ministryMember.findMany({
            where: { ministryId: parseInt(id) },
            select: { userId: true }
        })).map(m => m.userId);

        const users = await prisma.user.findMany({
            where: {
                id: { notIn: existingMemberIds },
                OR: [
                    { name: { contains: query, mode: 'insensitive' } },
                    { email: { contains: query, mode: 'insensitive' } }
                ]
            },
            select: {
                id: true,
                name: true,
                email: true,
                phoneNumber: true
            },
            take: 10
        });

        res.json(users);
    } catch (error) {
        console.error("Error in searchUsers:", error);
        res.status(500).json({ error: error.message });
    }
};

// 7. Add member directly by userId or email
exports.addMemberDirectly = async (req, res) => {
    try {
        const { id } = req.params;
        const callerId = req.user.id;
        const { userId, email } = req.body;

        const ministry = await prisma.ministry.findUnique({
            where: { id: parseInt(id) }
        });

        if (!ministry || !ministry.active) {
            return res.status(404).json({ error: "Ministerio no encontrado." });
        }

        const callerMembership = await getMembership(id, callerId);
        const isGlobalAdmin = req.user.role === 'ADMIN';
        const canAdd = isGlobalAdmin || callerMembership?.role === 'ADMIN' || (callerMembership?.status === 'ACTIVE' && ministry.allowMemberInvites);

        if (!canAdd) {
            return res.status(403).json({ error: "No tienes permiso para agregar miembros a este ministerio." });
        }

        let targetUser = null;
        if (userId) {
            targetUser = await prisma.user.findUnique({ where: { id: parseInt(userId) } });
        } else if (email) {
            targetUser = await prisma.user.findUnique({ where: { email: email.trim().toLowerCase() } });
        }

        if (!targetUser) {
            return res.status(404).json({ error: "El usuario a agregar no fue encontrado." });
        }

        // Check if already member
        const existing = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: parseInt(id),
                    userId: targetUser.id
                }
            }
        });

        if (existing) {
            if (existing.status === 'ACTIVE') {
                return res.status(400).json({ error: "El usuario ya es un miembro activo." });
            }
            // If was pending, activate directly
            const updated = await prisma.ministryMember.update({
                where: { id: existing.id },
                data: { status: 'ACTIVE' },
                include: {
                    user: { select: { id: true, name: true, email: true, phoneNumber: true } }
                }
            });
            return res.json({
                message: "Membresía activada exitosamente.",
                member: {
                    id: updated.id,
                    userId: updated.user.id,
                    name: updated.user.name,
                    email: updated.user.email,
                    phoneNumber: updated.user.phoneNumber,
                    role: updated.role,
                    joinedAt: updated.joinedAt
                }
            });
        }

        const newMember = await prisma.ministryMember.create({
            data: {
                ministryId: parseInt(id),
                userId: targetUser.id,
                role: 'MEMBER',
                status: 'ACTIVE'
            },
            include: {
                user: { select: { id: true, name: true, email: true, phoneNumber: true } }
            }
        });

        res.status(201).json({
            message: `${targetUser.name} ha sido agregado al ministerio.`,
            member: {
                id: newMember.id,
                userId: newMember.user.id,
                name: newMember.user.name,
                email: newMember.user.email,
                phoneNumber: newMember.user.phoneNumber,
                role: newMember.role,
                joinedAt: newMember.joinedAt
            }
        });
    } catch (error) {
        console.error("Error in addMemberDirectly:", error);
        res.status(500).json({ error: error.message });
    }
};

// 8. Handle pending join request (ACCEPT or REJECT)
exports.handlePendingRequest = async (req, res) => {
    try {
        const { id, userId } = req.params;
        const callerId = req.user.id;
        const { action } = req.body; // 'ACCEPT' or 'REJECT'

        if (!['ACCEPT', 'REJECT'].includes(action)) {
            return res.status(400).json({ error: "Acción inválida. Usa 'ACCEPT' o 'REJECT'." });
        }

        const ministry = await prisma.ministry.findUnique({
            where: { id: parseInt(id) }
        });

        if (!ministry) {
            return res.status(404).json({ error: "Ministerio no encontrado." });
        }

        const callerMembership = await getMembership(id, callerId);
        const isGlobalAdmin = req.user.role === 'ADMIN';
        const canManage = isGlobalAdmin || callerMembership?.role === 'ADMIN' || (callerMembership?.status === 'ACTIVE' && ministry.allowMemberInvites);

        if (!canManage) {
            return res.status(403).json({ error: "No tienes permiso para gestionar solicitudes en este ministerio." });
        }

        const targetMembership = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: parseInt(id),
                    userId: parseInt(userId)
                }
            }
        });

        if (!targetMembership || targetMembership.status !== 'PENDING') {
            return res.status(404).json({ error: "Solicitud no encontrada o ya resuelta." });
        }

        if (action === 'ACCEPT') {
            await prisma.ministryMember.update({
                where: { id: targetMembership.id },
                data: { status: 'ACTIVE' }
            });
            return res.json({ message: "Solicitud aceptada. El usuario ahora es miembro activo." });
        } else {
            await prisma.ministryMember.delete({
                where: { id: targetMembership.id }
            });
            return res.json({ message: "Solicitud rechazada." });
        }
    } catch (error) {
        console.error("Error in handlePendingRequest:", error);
        res.status(500).json({ error: error.message });
    }
};

// 9. Update member role (promote to ADMIN / demote to MEMBER)
// WHATSAPP-LIKE INVARIANT: At least 1 admin must remain at all times
exports.updateMemberRole = async (req, res) => {
    try {
        const { id, userId } = req.params;
        const callerId = req.user.id;
        const { role } = req.body;

        if (!['ADMIN', 'MEMBER'].includes(role)) {
            return res.status(400).json({ error: "Rol inválido. Debe ser 'ADMIN' o 'MEMBER'." });
        }

        const callerMembership = await getMembership(id, callerId);
        const isGlobalAdmin = req.user.role === 'ADMIN';

        if (!isGlobalAdmin && (!callerMembership || callerMembership.role !== 'ADMIN' || callerMembership.status !== 'ACTIVE')) {
            return res.status(403).json({ error: "Solo los administradores del grupo pueden cambiar roles de miembros." });
        }

        const targetMembership = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: parseInt(id),
                    userId: parseInt(userId)
                }
            }
        });

        if (!targetMembership || targetMembership.status !== 'ACTIVE') {
            return res.status(404).json({ error: "Miembro activo no encontrado." });
        }

        // WhatsApp invariant: If demoting from ADMIN to MEMBER, check remaining active admins
        if (targetMembership.role === 'ADMIN' && role === 'MEMBER') {
            const adminCount = await prisma.ministryMember.count({
                where: {
                    ministryId: parseInt(id),
                    role: 'ADMIN',
                    status: 'ACTIVE'
                }
            });

            if (adminCount <= 1) {
                return res.status(400).json({
                    error: "El ministerio debe tener al menos un administrador. Promueve a otro miembro a Administrador antes de realizar este cambio."
                });
            }
        }

        const updated = await prisma.ministryMember.update({
            where: { id: targetMembership.id },
            data: { role }
        });

        res.json({
            message: `Rol actualizado a ${role} exitosamente.`,
            member: updated
        });
    } catch (error) {
        console.error("Error in updateMemberRole:", error);
        res.status(500).json({ error: error.message });
    }
};

// 10. Remove a member or leave the ministry
// WHATSAPP-LIKE INVARIANT: Last remaining admin cannot leave if other members exist
exports.removeMember = async (req, res) => {
    try {
        const { id, userId } = req.params;
        const callerId = req.user.id;
        const targetUserId = parseInt(userId);

        const isLeavingVoluntarily = callerId === targetUserId;
        const callerMembership = await getMembership(id, callerId);
        const isGlobalAdmin = req.user.role === 'ADMIN';
        const isCallerAdmin = isGlobalAdmin || (callerMembership?.role === 'ADMIN' && callerMembership?.status === 'ACTIVE');

        if (!isLeavingVoluntarily && !isCallerAdmin) {
            return res.status(403).json({ error: "No tienes permiso para expulsar miembros de este ministerio." });
        }

        const targetMembership = await prisma.ministryMember.findUnique({
            where: {
                ministryId_userId: {
                    ministryId: parseInt(id),
                    userId: targetUserId
                }
            }
        });

        if (!targetMembership) {
            return res.status(404).json({ error: "El integrante no pertenece a este ministerio." });
        }

        // Check last admin invariant
        if (targetMembership.role === 'ADMIN' && targetMembership.status === 'ACTIVE') {
            const [adminCount, totalMemberCount] = await Promise.all([
                prisma.ministryMember.count({
                    where: { ministryId: parseInt(id), role: 'ADMIN', status: 'ACTIVE' }
                }),
                prisma.ministryMember.count({
                    where: { ministryId: parseInt(id), status: 'ACTIVE' }
                })
            ]);

            if (adminCount <= 1 && totalMemberCount > 1) {
                return res.status(400).json({
                    error: "No puedes dejar el ministerio sin administradores. Asigna a otro administrador antes de salir o elimina el ministerio."
                });
            }
        }

        await prisma.ministryMember.delete({
            where: { id: targetMembership.id }
        });

        res.json({
            message: isLeavingVoluntarily
                ? "Has salido del ministerio exitosamente."
                : "El integrante ha sido eliminado del ministerio."
        });
    } catch (error) {
        console.error("Error in removeMember:", error);
        res.status(500).json({ error: error.message });
    }
};

// 11. Regenerate invite code (only admins)
exports.regenerateInviteCode = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;

        const membership = await getMembership(id, userId);
        const isGlobalAdmin = req.user.role === 'ADMIN';

        if (!isGlobalAdmin && (!membership || membership.role !== 'ADMIN' || membership.status !== 'ACTIVE')) {
            return res.status(403).json({ error: "Solo los administradores pueden regenerar el enlace de invitación." });
        }

        const newInviteCode = crypto.randomUUID().slice(0, 8);

        const updated = await prisma.ministry.update({
            where: { id: parseInt(id) },
            data: { inviteCode: newInviteCode },
            select: { id: true, inviteCode: true }
        });

        res.json({
            message: "Enlace de invitación regenerado exitosamente.",
            inviteCode: updated.inviteCode
        });
    } catch (error) {
        console.error("Error in regenerateInviteCode:", error);
        res.status(500).json({ error: error.message });
    }
};

// 12. Delete ministry (only admins)
exports.deleteMinistry = async (req, res) => {
    try {
        const { id } = req.params;
        const userId = req.user.id;

        const membership = await getMembership(id, userId);
        const isGlobalAdmin = req.user.role === 'ADMIN';

        if (!isGlobalAdmin && (!membership || membership.role !== 'ADMIN' || membership.status !== 'ACTIVE')) {
            return res.status(403).json({ error: "Solo un administrador del grupo puede eliminar este ministerio." });
        }

        await prisma.ministry.delete({
            where: { id: parseInt(id) }
        });

        res.json({ message: "Ministerio eliminado correctamente." });
    } catch (error) {
        console.error("Error in deleteMinistry:", error);
        res.status(500).json({ error: error.message });
    }
};

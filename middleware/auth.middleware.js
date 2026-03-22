const prisma = require('../prismaClient');
const {
    hasSupabaseAuthConfig,
    getSupabaseUserFromToken
} = require('../services/supabase.service');

const getTokenFromRequest = (req) => {
    return req.cookies?.token || req.headers['authorization']?.split(' ')[1];
};

const resolveLocalUserFromSupabaseToken = async (token) => {
    if (!hasSupabaseAuthConfig) {
        return null;
    }

    const { data, error } = await getSupabaseUserFromToken(token);

    if (error || !data?.user?.email) {
        return null;
    }

    const userWithPermissions = await prisma.user.findUnique({
        where: { email: data.user.email },
        include: {
            role: {
                include: {
                    permissions: true
                }
            }
        }
    });

    if (!userWithPermissions) {
        return null;
    }

    const permissions = userWithPermissions.role.permissions.map(p => p.name);

    return {
        id: userWithPermissions.id,
        email: userWithPermissions.email,
        role: userWithPermissions.role.name,
        permissions,
        supabaseId: data.user.id
    };
};

exports.authenticateToken = (req, res, next) => {
    const token = getTokenFromRequest(req);

    if (!token) {
        return res.status(401).json({ error: 'Authentication required' });
    }

    resolveLocalUserFromSupabaseToken(token)
        .then((user) => {
            if (user) {
                req.user = user;
                return next();
            }

            return res.status(403).json({ error: 'Invalid or expired token' });
        })
        .catch((error) => {
            console.error('Auth middleware error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        });
};

exports.optionalAuth = (req, res, next) => {
    const token = getTokenFromRequest(req);
    if (!token) return next();

    resolveLocalUserFromSupabaseToken(token)
        .then((user) => {
            if (user) {
                req.user = user;
            }
            return next();
        })
        .catch(() => next());
};

exports.authorizeAdmin = (req, res, next) => {
    if (req.user && req.user.role === 'ADMIN') {
        next();
    } else {
        res.status(403).json({ error: 'Admin privileges required' });
    }
};

exports.authorizePermission = (permissionName) => {
    return async (req, res, next) => {
        try {
            if (!req.user || !req.user.id) {
                return res.status(401).json({ error: 'User not authenticated' });
            }

            // Always allow ADMIN (optional, but convenient)
            if (req.user.role === 'ADMIN') {
                return next();
            }

            const userWithPermissions = await prisma.user.findUnique({
                where: { id: req.user.id },
                include: {
                    role: {
                        include: { permissions: true }
                    }
                }
            });

            if (!userWithPermissions) {
                return res.status(403).json({ error: 'User not found' });
            }

            const hasPermission = userWithPermissions.role.permissions.some(p => p.name === permissionName);

            if (hasPermission) {
                next();
            } else {
                res.status(403).json({ error: `Missing permission: ${permissionName} ` });
            }
        } catch (error) {
            console.error('Permission check error:', error);
            res.status(500).json({ error: 'Internal server error' });
        }
    };
};

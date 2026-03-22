const prisma = require('../prismaClient');
const {
    hasSupabaseAuthConfig,
    getSupabaseUserFromToken,
    refreshSupabaseSession
} = require('../services/supabase.service');

const REFRESH_COOKIE_NAME = 'refresh_token';
const REFRESH_COOKIE_MAX_AGE_MS = (Number(process.env.REFRESH_TOKEN_COOKIE_DAYS) || 30) * 24 * 60 * 60 * 1000;

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

const setRefreshedAuthCookies = (res, session) => {
    if (!session?.access_token) return;

    const accessTokenTtlMs = (session.expires_in || 60 * 60) * 1000;

    res.cookie('token', session.access_token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        maxAge: accessTokenTtlMs,
        sameSite: 'lax'
    });

    if (session.refresh_token) {
        res.cookie(REFRESH_COOKIE_NAME, session.refresh_token, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: REFRESH_COOKIE_MAX_AGE_MS,
            sameSite: 'lax'
        });
    }
};

const resolveUserWithOptionalRefresh = async (req, res) => {
    const token = getTokenFromRequest(req);
    if (token) {
        const user = await resolveLocalUserFromSupabaseToken(token);
        if (user) {
            return user;
        }
    }

    const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!refreshToken) {
        return null;
    }

    const { data: refreshData, error: refreshError } = await refreshSupabaseSession(refreshToken);
    const refreshedSession = refreshData?.session;

    if (refreshError || !refreshedSession?.access_token) {
        return null;
    }

    const user = await resolveLocalUserFromSupabaseToken(refreshedSession.access_token);
    if (!user) {
        return null;
    }

    setRefreshedAuthCookies(res, refreshedSession);
    return user;
};

exports.authenticateToken = (req, res, next) => {
    resolveUserWithOptionalRefresh(req, res)
        .then((user) => {
            if (user) {
                req.user = user;
                return next();
            }

            return res.status(401).json({ error: 'Authentication required' });
        })
        .catch((error) => {
            console.error('Auth middleware error:', error);
            return res.status(500).json({ error: 'Internal server error' });
        });
};

exports.optionalAuth = (req, res, next) => {
    resolveUserWithOptionalRefresh(req, res)
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

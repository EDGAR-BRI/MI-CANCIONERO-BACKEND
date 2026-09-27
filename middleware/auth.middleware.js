const prisma = require('../prismaClient');
const jwtService = require('../services/jwt.service');

const REFRESH_COOKIE_NAME = 'refresh_token';
const ACCESS_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const getTokenFromRequest = (req) => {
    return req.cookies?.token || req.headers['authorization']?.split(' ')[1];
};

const resolveUserWithOptionalRefresh = async (req, res) => {
    const token = getTokenFromRequest(req);

    if (token) {
        const decoded = jwtService.verifyToken(token);
        if (decoded) {
            return decoded;
        }
    }

    // Attempt auto-refresh via refresh_token cookie
    const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
    if (!refreshToken) {
        return null;
    }

    const refreshDecoded = jwtService.verifyRefreshToken(refreshToken);
    if (!refreshDecoded?.id) {
        return null;
    }

    try {
        const user = await prisma.user.findUnique({
            where: { id: refreshDecoded.id },
            include: {
                role: {
                    include: {
                        permissions: true
                    }
                }
            }
        });

        if (!user) {
            return null;
        }

        const { token: newAccessToken } = jwtService.generateTokens(user);

        // Update token cookie
        res.cookie('token', newAccessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax',
            path: '/',
            maxAge: ACCESS_COOKIE_MAX_AGE_MS
        });

        return {
            id: user.id,
            email: user.email,
            name: user.name,
            avatarUrl: user.avatarUrl || null,
            role: user.role.name,
            permissions: user.role.permissions.map(p => p.name)
        };
    } catch (error) {
        console.error('Error refreshing token in auth middleware:', error);
        return null;
    }
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
        return next();
    }
    return res.status(403).json({ error: 'Admin privileges required' });
};

exports.authorizePermission = (permissionName) => {
    return (req, res, next) => {
        if (!req.user || !req.user.id) {
            return res.status(401).json({ error: 'User not authenticated' });
        }

        // Always allow ADMIN
        if (req.user.role === 'ADMIN') {
            return next();
        }

        const hasPerm = Array.isArray(req.user.permissions) && req.user.permissions.includes(permissionName);
        if (hasPerm) {
            return next();
        }

        return res.status(403).json({ error: `Missing permission: ${permissionName}` });
    };
};

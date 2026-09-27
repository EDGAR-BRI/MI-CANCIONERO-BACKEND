require('dotenv').config();
const jwt = require('jsonwebtoken');

const getSecret = () => process.env.JWT_SECRET || 'cancionero-jwt-secret-dev-2026';
const ACCESS_TOKEN_EXPIRES_IN = process.env.JWT_EXPIRES_IN || '7d';
const REFRESH_TOKEN_EXPIRES_IN = '30d';

/**
 * Generate Access Token and Refresh Token for an authenticated user
 */
const generateTokens = (user) => {
    let permissions = [];
    if (user.role?.permissions) {
        permissions = user.role.permissions.map(p => typeof p === 'string' ? p : p.name);
    } else if (Array.isArray(user.permissions)) {
        permissions = user.permissions.map(p => typeof p === 'string' ? p : p.name);
    }

    const roleName = typeof user.role === 'object' ? user.role?.name : user.role;

    const payload = {
        id: user.id,
        email: user.email,
        name: user.name,
        avatarUrl: user.avatarUrl || null,
        role: roleName || 'USER',
        permissions
    };

    const token = jwt.sign(payload, getSecret(), {
        expiresIn: ACCESS_TOKEN_EXPIRES_IN
    });

    const refreshToken = jwt.sign(
        { id: user.id, type: 'refresh' },
        getSecret(),
        { expiresIn: REFRESH_TOKEN_EXPIRES_IN }
    );

    return { token, refreshToken };
};

/**
 * Verify an Access Token
 */
const verifyToken = (token) => {
    try {
        return jwt.verify(token, getSecret());
    } catch (error) {
        return null;
    }
};

/**
 * Verify a Refresh Token
 */
const verifyRefreshToken = (refreshToken) => {
    try {
        const decoded = jwt.verify(refreshToken, getSecret());
        if (decoded.type !== 'refresh') return null;
        return decoded;
    } catch (error) {
        return null;
    }
};

module.exports = {
    generateTokens,
    verifyToken,
    verifyRefreshToken,
    get JWT_SECRET() {
        return getSecret();
    }
};

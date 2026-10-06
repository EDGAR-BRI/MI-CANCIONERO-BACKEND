const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const { validatePhoneNumber } = require('../utils/validation');
const jwtService = require('../services/jwt.service');
const googleService = require('../services/google.service');

const REFRESH_COOKIE_NAME = 'refresh_token';
const REFRESH_COOKIE_MAX_AGE_MS = (Number(process.env.REFRESH_TOKEN_COOKIE_DAYS) || 30) * 24 * 60 * 60 * 1000;
const ACCESS_COOKIE_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000; // 7 days

const getDefaultUserRole = async () => {
    let role = await prisma.role.findFirst({ where: { name: 'USER' } });
    if (!role) {
        role = await prisma.role.findFirst();
    }
    if (!role) {
        role = await prisma.role.create({
            data: { name: 'USER' }
        });
    }
    return role;
};

const setAuthCookies = (res, { token, refreshToken, rememberMe = true }) => {
    const isProduction = process.env.NODE_ENV === 'production';
    const baseCookieOptions = {
        httpOnly: true,
        secure: isProduction,
        sameSite: isProduction ? 'none' : 'lax',
        path: '/'
    };

    res.cookie('token', token, {
        ...baseCookieOptions,
        maxAge: ACCESS_COOKIE_MAX_AGE_MS
    });

    if (refreshToken) {
        res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
            ...baseCookieOptions,
            ...(rememberMe ? { maxAge: REFRESH_COOKIE_MAX_AGE_MS } : {})
        });
    }
};

// 1. Register with email and password
exports.register = async (req, res) => {
    const { name, email, password, phoneNumber } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Nombre, correo y contraseña son obligatorios.' });
    }

    if (String(password).length < 6) {
        return res.status(400).json({ error: 'La contraseña debe tener al menos 6 caracteres.' });
    }

    try {
        const normalizedEmail = email.trim().toLowerCase();

        // Check if user already exists
        const existingUser = await prisma.user.findUnique({
            where: { email: normalizedEmail }
        });

        if (existingUser) {
            if (existingUser.googleId) {
                return res.status(409).json({
                    error: 'Este correo ya está registrado con Google. Por favor, inicia sesión con el botón Continuar con Google.'
                });
            }
            return res.status(409).json({ error: 'El correo electrónico ya está registrado.' });
        }

        let validPhone = null;
        if (phoneNumber) {
            validPhone = validatePhoneNumber(phoneNumber);
            if (!validPhone) {
                return res.status(400).json({ error: 'Número de teléfono inválido.' });
            }
        }

        const hashedPassword = await bcrypt.hash(password, 10);
        const role = await getDefaultUserRole();

        const user = await prisma.user.create({
            data: {
                name: name.trim(),
                email: normalizedEmail,
                password: hashedPassword,
                roleId: role.id,
                phoneNumber: validPhone
            },
            include: {
                role: {
                    include: {
                        permissions: true
                    }
                }
            }
        });

        const { token, refreshToken } = jwtService.generateTokens(user);
        setAuthCookies(res, { token, refreshToken });

        res.status(201).json({
            message: 'Cuenta creada exitosamente.',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl || null,
                phoneNumber: user.phoneNumber || null,
                isGoogleUser: false,
                role: user.role.name,
                permissions: user.role.permissions.map(p => p.name)
            }
        });
    } catch (error) {
        console.error('Error in auth.register:', error);
        res.status(500).json({ error: 'Error al registrar usuario. Intenta nuevamente.' });
    }
};

// 2. Login with email and password
exports.login = async (req, res) => {
    const { email, password, rememberMe = true } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Correo y contraseña son obligatorios.' });
    }

    try {
        const normalizedEmail = email.trim().toLowerCase();

        const user = await prisma.user.findUnique({
            where: { email: normalizedEmail },
            include: {
                role: {
                    include: {
                        permissions: true
                    }
                }
            }
        });

        if (!user) {
            return res.status(401).json({ error: 'Credenciales inválidas. Verifica tu correo y contraseña.' });
        }

        const isPasswordValid = await bcrypt.compare(password, user.password);
        if (!isPasswordValid) {
            if (user.googleId) {
                return res.status(401).json({
                    error: 'Contraseña incorrecta. Tu cuenta está vinculada a Google, puedes iniciar sesión con Google.'
                });
            }
            return res.status(401).json({ error: 'Credenciales inválidas. Verifica tu correo y contraseña.' });
        }

        const { token, refreshToken } = jwtService.generateTokens(user);
        setAuthCookies(res, { token, refreshToken, rememberMe });

        res.json({
            message: 'Inicio de sesión exitoso.',
            token,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl || null,
                phoneNumber: user.phoneNumber || null,
                isGoogleUser: Boolean(user.googleId),
                role: user.role.name,
                permissions: user.role.permissions.map(p => p.name)
            }
        });
    } catch (error) {
        console.error('Error in auth.login:', error);
        res.status(500).json({ error: 'Error al iniciar sesión. Intenta nuevamente.' });
    }
};

// 3. Initiate Google OAuth flow
exports.googleLogin = async (req, res) => {
    try {
        const redirectUri = req.query.redirect_uri || req.query.redirectUri;
        const url = googleService.getGoogleAuthUrl(redirectUri);

        if (req.query.json === 'true' || req.headers.accept?.includes('application/json')) {
            return res.json({ url });
        }

        return res.redirect(url);
    } catch (error) {
        console.error('Error in auth.googleLogin:', error);
        return res.status(500).json({ error: error.message || 'Error al iniciar sesión con Google.' });
    }
};

// 4. Handle Google OAuth callback & Account Linking
exports.googleCallback = async (req, res) => {
    const { code, accessToken, redirectUri } = req.body;

    if (!code && !accessToken) {
        return res.status(400).json({ error: 'Código de autorización o token de acceso requerido.' });
    }

    try {
        let googleAccessToken = accessToken;

        if (code) {
            // Exchange code with Google
            const tokenData = await googleService.exchangeGoogleCode(code, redirectUri);
            if (!tokenData?.access_token) {
                return res.status(401).json({ error: 'No se pudo obtener el token de acceso de Google.' });
            }
            googleAccessToken = tokenData.access_token;
        }

        // Fetch user profile from Google
        const googleUser = await googleService.getGoogleUserInfo(googleAccessToken);
        if (!googleUser?.email) {
            return res.status(400).json({ error: 'No se pudo obtener el correo de la cuenta de Google.' });
        }

        const normalizedEmail = googleUser.email.trim().toLowerCase();

        // Account Linking: Check if user already exists by email OR googleId
        let user = await prisma.user.findFirst({
            where: {
                OR: [
                    { email: normalizedEmail },
                    { googleId: googleUser.sub }
                ]
            },
            include: {
                role: {
                    include: { permissions: true }
                }
            }
        });

        if (user) {
            // Link Google account and update avatar/name if applicable
            const updateData = {};
            if (!user.googleId) {
                updateData.googleId = googleUser.sub;
            }
            // Update avatar from Google only if user has no avatar or already uses Google photo
            if (googleUser.picture && (!user.avatarUrl || user.avatarUrl.includes('googleusercontent.com'))) {
                updateData.avatarUrl = googleUser.picture;
            }
            if ((!user.name || user.name.trim() === '') && googleUser.name) {
                updateData.name = googleUser.name;
            }

            if (Object.keys(updateData).length > 0) {
                user = await prisma.user.update({
                    where: { id: user.id },
                    data: updateData,
                    include: {
                        role: {
                            include: { permissions: true }
                        }
                    }
                });
            }
        } else {
            // Create new user linked to Google
            const defaultRole = await getDefaultUserRole();
            const randomPassword = crypto.randomUUID();
            const hashedPassword = await bcrypt.hash(randomPassword, 10);

            user = await prisma.user.create({
                data: {
                    name: googleUser.name || normalizedEmail.split('@')[0],
                    email: normalizedEmail,
                    password: hashedPassword,
                    googleId: googleUser.sub,
                    avatarUrl: googleUser.picture || null,
                    roleId: defaultRole.id
                },
                include: {
                    role: {
                        include: { permissions: true }
                    }
                }
            });
        }

        // Generate native JWT tokens
        const { token, refreshToken } = jwtService.generateTokens(user);
        setAuthCookies(res, { token, refreshToken, rememberMe: true });

        return res.json({
            message: 'Inicio de sesión con Google exitoso.',
            token,
            refreshToken,
            user: {
                id: user.id,
                name: user.name,
                email: user.email,
                avatarUrl: user.avatarUrl || null,
                phoneNumber: user.phoneNumber || null,
                isGoogleUser: true,
                role: user.role?.name || 'USER',
                permissions: user.role?.permissions?.map(p => p.name) || []
            }
        });
    } catch (error) {
        console.error('Error in auth.googleCallback:', error.response?.data || error);
        const errDetail = error.response?.data?.error_description || error.response?.data?.error || error.message;
        return res.status(500).json({ error: `Error al procesar la autenticación con Google: ${errDetail}` });
    }
};

// 5. Logout
exports.logout = (req, res) => {
    res.clearCookie('token', { path: '/' });
    res.clearCookie(REFRESH_COOKIE_NAME, { path: '/' });
    res.json({ message: 'Sesión cerrada exitosamente.' });
};

// 6. Current authenticated user
exports.me = (req, res) => {
    res.json({ user: req.user });
};

// 7. Update current user's profile (name, avatarUrl, phoneNumber)
exports.updateProfile = async (req, res) => {
    try {
        const userId = Number(req.user?.id);
        if (!userId || isNaN(userId)) {
            return res.status(401).json({ error: 'Usuario no autenticado válido.' });
        }
        const { name, avatarUrl, phoneNumber, currentPassword, newPassword } = req.body;

        const updateData = {};
        if (name !== undefined) {
            if (!name || !name.trim()) {
                return res.status(400).json({ error: 'El nombre no puede estar vacío.' });
            }
            updateData.name = name.trim();
        }

        if (avatarUrl !== undefined) {
            updateData.avatarUrl = avatarUrl && avatarUrl.trim() ? avatarUrl.trim() : null;
        }

        if (phoneNumber !== undefined) {
            if (phoneNumber && phoneNumber.trim()) {
                const validPhone = validatePhoneNumber(phoneNumber.trim());
                if (!validPhone) {
                    return res.status(400).json({ error: 'Número de teléfono inválido.' });
                }
                updateData.phoneNumber = validPhone;
            } else {
                updateData.phoneNumber = null;
            }
        }

        if (currentPassword && (!newPassword || !newPassword.trim())) {
            return res.status(400).json({ error: 'Debes ingresar una nueva contraseña.' });
        }

        if (newPassword !== undefined && newPassword !== '') {
            if (String(newPassword).length < 6) {
                return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 6 caracteres.' });
            }

            const userRecord = await prisma.user.findUnique({ where: { id: userId } });
            if (!userRecord) {
                return res.status(404).json({ error: 'Usuario no encontrado.' });
            }

            // Si el usuario no fue creado con Google, o si envió contraseña actual, validarla
            if (!userRecord.googleId || currentPassword) {
                if (!currentPassword) {
                    return res.status(400).json({ error: 'Debes ingresar tu contraseña actual para cambiarla.' });
                }
                const isMatch = await bcrypt.compare(currentPassword, userRecord.password);
                if (!isMatch) {
                    return res.status(400).json({ error: 'La contraseña actual es incorrecta.' });
                }
            }

            updateData.password = await bcrypt.hash(newPassword, 10);
        }

        if (Object.keys(updateData).length === 0) {
            return res.status(400).json({ error: 'No se enviaron campos para actualizar.' });
        }

        const updatedUser = await prisma.user.update({
            where: { id: userId },
            data: updateData,
            include: {
                role: {
                    include: { permissions: true }
                }
            }
        });

        // Re-generate tokens with new profile data and update cookies
        const { token, refreshToken } = jwtService.generateTokens(updatedUser);
        setAuthCookies(res, { token, refreshToken, rememberMe: true });

        return res.json({
            message: 'Perfil actualizado exitosamente.',
            token,
            refreshToken,
            user: {
                id: updatedUser.id,
                name: updatedUser.name,
                email: updatedUser.email,
                avatarUrl: updatedUser.avatarUrl || null,
                phoneNumber: updatedUser.phoneNumber || null,
                isGoogleUser: Boolean(updatedUser.googleId),
                role: updatedUser.role?.name || 'USER',
                permissions: updatedUser.role?.permissions?.map(p => p.name) || []
            }
        });
    } catch (error) {
        console.error('Error in auth.updateProfile:', error);
        return res.status(500).json({ error: 'Error al actualizar el perfil.' });
    }
};


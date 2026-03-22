const prisma = require('../prismaClient');
const bcrypt = require('bcryptjs');
const { validatePhoneNumber } = require('../utils/validation');
const {
    hasSupabaseAuthConfig,
    signInWithSupabase,
    signUpWithSupabase,
    sendPasswordRecoveryEmail,
    resendSignupVerificationEmail,
    updatePasswordWithAccessToken
} = require('../services/supabase.service');

const SUPABASE_PASSWORD_PLACEHOLDER = 'SUPABASE_MANAGED_PASSWORD';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:4321';
const REFRESH_COOKIE_NAME = 'refresh_token';
const REFRESH_COOKIE_MAX_AGE_MS = (Number(process.env.REFRESH_TOKEN_COOKIE_DAYS) || 30) * 24 * 60 * 60 * 1000;

const logInternalError = (scope, error) => {
    console.error(`[${scope}]`, error);
};

const isPrismaUniqueConstraintError = (error) => {
    return error && error.code === 'P2002';
};

const getDefaultUserRole = async () => {
    let role = await prisma.role.findUnique({ where: { name: 'USER' } });
    if (!role) role = { id: 2, name: 'USER' };
    return role;
};

const findUserWithAuthDataByEmail = async (email) => {
    return prisma.user.findUnique({
        where: { email },
        include: {
            role: {
                include: {
                    permissions: true
                }
            }
        }
    });
};

exports.login = async (req, res) => {
    const { email, password, rememberMe = true } = req.body;

    if (!email || !password) {
        return res.status(400).json({ error: 'Email y password son obligatorios' });
    }

    try {
        if (!hasSupabaseAuthConfig) {
            return res.status(500).json({ error: 'Supabase Auth no esta configurado en el backend' });
        }

        const { data: signInData, error: signInError } = await signInWithSupabase(email, password);

        if (signInError?.message && /email not confirmed/i.test(signInError.message)) {
            return res.status(403).json({ error: 'Debes verificar tu correo antes de iniciar sesion' });
        }

        if (signInError || !signInData?.session?.access_token || !signInData?.user) {
            return res.status(401).json({ error: 'Credenciales invalidas' });
        }

        let user = await findUserWithAuthDataByEmail(signInData.user.email);

        if (!user) {
            const role = await getDefaultUserRole();
            const fallbackHash = await bcrypt.hash(SUPABASE_PASSWORD_PLACEHOLDER, 10);

            user = await prisma.user.create({
                data: {
                    name: signInData.user.user_metadata?.name || signInData.user.email,
                    email: signInData.user.email,
                    password: fallbackHash,
                    roleId: role.id,
                    phoneNumber: signInData.user.phone || null
                },
                include: {
                    role: {
                        include: {
                            permissions: true
                        }
                    }
                }
            });
        }

        const token = signInData.session.access_token;
        const refreshToken = signInData.session.refresh_token;
        const permissions = user.role.permissions.map(p => p.name);
        const accessTokenMaxAgeMs = (signInData.session.expires_in || 24 * 60 * 60) * 1000;

        const baseCookieOptions = {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            sameSite: 'lax'
        };

        // Access token cookie
        res.cookie('token', token, {
            ...baseCookieOptions,
            ...(rememberMe ? { maxAge: accessTokenMaxAgeMs } : {})
        });

        // Refresh token cookie for transparent renewals
        if (refreshToken) {
            res.cookie(REFRESH_COOKIE_NAME, refreshToken, {
                ...baseCookieOptions,
                ...(rememberMe ? { maxAge: REFRESH_COOKIE_MAX_AGE_MS } : {})
            });
        }

        res.json({
            message: 'Login successful',
            token,
            refreshToken,
            expiresIn: signInData.session.expires_in,
            user: {
                id: user.id,
                email: user.email,
                role: user.role.name,
                permissions
            }
        });
    } catch (error) {
        logInternalError('auth.login', error);
        res.status(500).json({ error: 'No se pudo iniciar sesion. Intenta nuevamente.' });
    }
};

exports.register = async (req, res) => {
    const { name, email, password, phoneNumber } = req.body;

    if (!name || !email || !password) {
        return res.status(400).json({ error: 'Name, email and password are required' });
    }

    try {
        if (!hasSupabaseAuthConfig) {
            return res.status(500).json({ error: 'Supabase Auth no esta configurado en el backend' });
        }

        if (phoneNumber) {
            const validPhone = validatePhoneNumber(phoneNumber);
            if (!validPhone) {
                return res.status(400).json({ error: 'Invalid phone number' });
            }
        }
        const existingUser = await prisma.user.findUnique({ where: { email } });
        if (existingUser) {
            return res.status(409).json({ error: 'El usuario ya existe.' });
        }

        const { data: signUpData, error: signUpError } = await signUpWithSupabase({
            email,
            password,
            metadata: {
                name,
                phoneNumber: phoneNumber || null
            },
            emailRedirectTo: `${FRONTEND_URL}/login?verified=1`
        });

        if (signUpError) {
            const alreadyExists = /already registered|already exists|user already exists/i.test(signUpError.message || '');
            if (alreadyExists) {
                return res.status(409).json({ error: 'El correo ya esta registrado.' });
            }
            return res.status(400).json({ error: 'No se pudo completar el registro. Verifica tus datos.' });
        }

        const supabaseEmail = signUpData?.user?.email || signUpData?.user?.identities?.[0]?.identity_data?.email || email;

        const hashedPassword = await bcrypt.hash(SUPABASE_PASSWORD_PLACEHOLDER, 10);

        const role = await getDefaultUserRole();

        const user = await prisma.user.create({
            data: {
                name,
                email: supabaseEmail,
                password: hashedPassword,
                roleId: role.id,
                phoneNumber: phoneNumber ? validatePhoneNumber(phoneNumber) : null
            }
        });

        res.status(201).json({
            message: 'Cuenta creada. Te enviamos un correo para confirmar tu email antes de iniciar sesion.',
            user: { id: user.id, email: user.email, name: user.name }
        });
    } catch (error) {
        logInternalError('auth.register', error);

        if (isPrismaUniqueConstraintError(error)) {
            return res.status(409).json({ error: 'El correo ya esta registrado.' });
        }

        return res.status(500).json({ error: 'No se pudo crear la cuenta. Intenta nuevamente.' });
    }
};

exports.resendVerification = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email es obligatorio' });
    }

    if (!hasSupabaseAuthConfig) {
        return res.status(500).json({ error: 'Supabase Auth no esta configurado en el backend' });
    }

    try {
        const redirectTo = `${FRONTEND_URL}/login?verified=1`;
        await resendSignupVerificationEmail({ email, redirectTo });

        return res.json({
            message: 'Si el correo existe, enviamos un nuevo enlace de verificacion.'
        });
    } catch (error) {
        logInternalError('auth.resendVerification', error);
        return res.status(500).json({ error: 'No se pudo procesar la solicitud. Intenta nuevamente.' });
    }
};

exports.forgotPassword = async (req, res) => {
    const { email } = req.body;

    if (!email) {
        return res.status(400).json({ error: 'Email es obligatorio' });
    }

    if (!hasSupabaseAuthConfig) {
        return res.status(500).json({ error: 'Supabase Auth no esta configurado en el backend' });
    }

    try {
        const redirectTo = `${FRONTEND_URL}/reset-password`;
        await sendPasswordRecoveryEmail({ email, redirectTo });

        return res.json({
            message: 'Si el correo existe, enviamos instrucciones para recuperar la contrasena.'
        });
    } catch (error) {
        logInternalError('auth.forgotPassword', error);
        return res.status(500).json({ error: 'No se pudo procesar la solicitud. Intenta nuevamente.' });
    }
};

exports.resetPassword = async (req, res) => {
    const { accessToken, newPassword } = req.body;

    if (!accessToken || !newPassword || String(newPassword).length < 6) {
        return res.status(400).json({ error: 'Token y nueva contrasena (min 6) son obligatorios' });
    }

    if (!hasSupabaseAuthConfig) {
        return res.status(500).json({ error: 'Supabase Auth no esta configurado en el backend' });
    }

    try {
        const { error } = await updatePasswordWithAccessToken({
            accessToken,
            newPassword
        });

        if (error) {
            return res.status(400).json({ error: 'El enlace no es valido o ya expiro. Solicita uno nuevo.' });
        }

        return res.json({ message: 'Contrasena actualizada correctamente' });
    } catch (error) {
        logInternalError('auth.resetPassword', error);
        return res.status(500).json({ error: 'No se pudo actualizar la contrasena. Intenta nuevamente.' });
    }
};

exports.logout = (req, res) => {
    res.clearCookie('token');
    res.clearCookie(REFRESH_COOKIE_NAME);
    res.json({ message: 'Logged out successfully' });
};

exports.me = (req, res) => {
    // If middleware passed, req.user is set
    res.json({ user: req.user });
};

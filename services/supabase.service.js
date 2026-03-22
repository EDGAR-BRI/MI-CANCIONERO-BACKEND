const { createClient } = require('@supabase/supabase-js');

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseAnonKey = process.env.SUPABASE_ANON_KEY;
const supabaseServiceRoleKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

const hasValidServiceRoleKey = Boolean(
    supabaseServiceRoleKey &&
    !supabaseServiceRoleKey.startsWith('YOUR_')
);

const hasSupabaseAuthConfig = Boolean(supabaseUrl && supabaseAnonKey);

const authClient = hasSupabaseAuthConfig
    ? createClient(supabaseUrl, supabaseAnonKey, {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    })
    : null;

const adminClient = supabaseUrl && hasValidServiceRoleKey
    ? createClient(supabaseUrl, supabaseServiceRoleKey, {
        auth: {
            autoRefreshToken: false,
            persistSession: false
        }
    })
    : null;

const signInWithSupabase = async (email, password) => {
    if (!authClient) {
        return { data: null, error: { message: 'Supabase auth is not configured' } };
    }

    return authClient.auth.signInWithPassword({ email, password });
};

const signUpWithSupabase = async ({ email, password, metadata = {}, emailRedirectTo }) => {
    if (!authClient) {
        return { data: null, error: { message: 'Supabase auth is not configured' } };
    }

    return authClient.auth.signUp({
        email,
        password,
        options: {
            data: metadata,
            emailRedirectTo
        }
    });
};

const sendPasswordRecoveryEmail = async ({ email, redirectTo }) => {
    if (!authClient) {
        return { data: null, error: { message: 'Supabase auth is not configured' } };
    }

    return authClient.auth.resetPasswordForEmail(email, {
        redirectTo
    });
};

const resendSignupVerificationEmail = async ({ email, redirectTo }) => {
    if (!authClient) {
        return { data: null, error: { message: 'Supabase auth is not configured' } };
    }

    return authClient.auth.resend({
        type: 'signup',
        email,
        options: {
            emailRedirectTo: redirectTo
        }
    });
};

const updatePasswordWithAccessToken = async ({ accessToken, newPassword }) => {
    if (!authClient) {
        return { data: null, error: { message: 'Supabase auth is not configured' } };
    }

    if (!adminClient) {
        return { data: null, error: { message: 'Supabase service role key is required for password update' } };
    }

    const { data, error } = await authClient.auth.getUser(accessToken);
    if (error || !data?.user?.id) {
        return { data: null, error: error || { message: 'Invalid or expired recovery token' } };
    }

    return adminClient.auth.admin.updateUserById(data.user.id, {
        password: newPassword
    });
};

const createUserWithSupabaseAdmin = async ({ email, password, metadata = {}, emailConfirm = false }) => {
    if (!adminClient) {
        return { data: null, error: { message: 'Supabase service role key is not configured' } };
    }

    return adminClient.auth.admin.createUser({
        email,
        password,
        user_metadata: metadata,
        email_confirm: emailConfirm
    });
};

const getSupabaseUserFromToken = async (accessToken) => {
    if (!authClient) {
        return { data: { user: null }, error: { message: 'Supabase auth is not configured' } };
    }

    return authClient.auth.getUser(accessToken);
};

module.exports = {
    hasSupabaseAuthConfig,
    hasValidServiceRoleKey,
    signInWithSupabase,
    signUpWithSupabase,
    sendPasswordRecoveryEmail,
    resendSignupVerificationEmail,
    updatePasswordWithAccessToken,
    createUserWithSupabaseAdmin,
    getSupabaseUserFromToken
};
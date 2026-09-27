require('dotenv').config();
const axios = require('axios');

const getClientId = () => process.env.GOOGLE_CLIENT_ID || process.env.id;
const getClientSecret = () => process.env.GOOGLE_CLIENT_SECRET || process.env.secreto;
const getDefaultRedirectUri = (customUri) => {
    if (customUri) return customUri;
    return process.env.GOOGLE_REDIRECT_URI || `${process.env.FRONTEND_URL || 'http://localhost:4321'}/auth/callback`;
};

/**
 * Generate Google OAuth authorization URL
 */
const getGoogleAuthUrl = (redirectUri) => {
    const clientId = getClientId();
    if (!clientId) {
        throw new Error("GOOGLE_CLIENT_ID no está configurado en el archivo .env del backend.");
    }

    const effectiveRedirectUri = getDefaultRedirectUri(redirectUri);
    const rootUrl = 'https://accounts.google.com/o/oauth2/v2/auth';
    const params = new URLSearchParams({
        client_id: clientId,
        redirect_uri: effectiveRedirectUri,
        response_type: 'code',
        scope: 'openid email profile',
        access_type: 'offline',
        prompt: 'consent'
    });

    return `${rootUrl}?${params.toString()}`;
};

/**
 * Exchange authorization code for Google access token and ID token
 */
const exchangeGoogleCode = async (code, redirectUri) => {
    const clientId = getClientId();
    const clientSecret = getClientSecret();
    if (!clientId || !clientSecret) {
        throw new Error("GOOGLE_CLIENT_ID o GOOGLE_CLIENT_SECRET no están configurados en el .env.");
    }

    const effectiveRedirectUri = getDefaultRedirectUri(redirectUri);

    const response = await axios.post(
        'https://oauth2.googleapis.com/token',
        {
            code,
            client_id: clientId,
            client_secret: clientSecret,
            redirect_uri: effectiveRedirectUri,
            grant_type: 'authorization_code'
        },
        {
            headers: {
                'Content-Type': 'application/json'
            }
        }
    );

    return response.data; // { access_token, expires_in, id_token, refresh_token, token_type }
};

/**
 * Fetch user profile from Google using the access token
 */
const getGoogleUserInfo = async (accessToken) => {
    const response = await axios.get('https://www.googleapis.com/oauth2/v3/userinfo', {
        headers: {
            Authorization: `Bearer ${accessToken}`
        }
    });

    return response.data; // { sub, name, given_name, family_name, picture, email, email_verified }
};

module.exports = {
    getGoogleAuthUrl,
    exchangeGoogleCode,
    getGoogleUserInfo,
    get hasGoogleConfig() {
        return Boolean(getClientId() && getClientSecret());
    }
};

const axios = require('axios');

const FALLBACK_PREFIXES = [
    { iso2: 'AR', country: 'Argentina', code: '+54', label: 'AR +54' },
    { iso2: 'BO', country: 'Bolivia', code: '+591', label: 'BO +591' },
    { iso2: 'BR', country: 'Brasil', code: '+55', label: 'BR +55' },
    { iso2: 'CL', country: 'Chile', code: '+56', label: 'CL +56' },
    { iso2: 'CO', country: 'Colombia', code: '+57', label: 'CO +57' },
    { iso2: 'CR', country: 'Costa Rica', code: '+506', label: 'CR +506' },
    { iso2: 'DO', country: 'Republica Dominicana', code: '+1', label: 'DO +1' },
    { iso2: 'EC', country: 'Ecuador', code: '+593', label: 'EC +593' },
    { iso2: 'ES', country: 'Espana', code: '+34', label: 'ES +34' },
    { iso2: 'GT', country: 'Guatemala', code: '+502', label: 'GT +502' },
    { iso2: 'HN', country: 'Honduras', code: '+504', label: 'HN +504' },
    { iso2: 'MX', country: 'Mexico', code: '+52', label: 'MX +52' },
    { iso2: 'NI', country: 'Nicaragua', code: '+505', label: 'NI +505' },
    { iso2: 'PA', country: 'Panama', code: '+507', label: 'PA +507' },
    { iso2: 'PE', country: 'Peru', code: '+51', label: 'PE +51' },
    { iso2: 'PY', country: 'Paraguay', code: '+595', label: 'PY +595' },
    { iso2: 'SV', country: 'El Salvador', code: '+503', label: 'SV +503' },
    { iso2: 'US', country: 'Estados Unidos', code: '+1', label: 'US +1' },
    { iso2: 'UY', country: 'Uruguay', code: '+598', label: 'UY +598' },
    { iso2: 'VE', country: 'Venezuela', code: '+58', label: 'VE +58' }
];

const CACHE_TTL_MS = 24 * 60 * 60 * 1000;
let phonePrefixCache = {
    expiresAt: 0,
    data: null
};

const normalizePrefixes = (countries) => {
    const bestByIso2 = new Map();

    for (const country of countries) {
        const iso2 = country?.cca2;
        const countryName = country?.name?.common;
        const root = country?.idd?.root;
        const suffixes = country?.idd?.suffixes;

        if (!iso2 || !countryName || !root || !Array.isArray(suffixes) || suffixes.length === 0) {
            continue;
        }

        for (const suffix of suffixes) {
            const code = `${root}${suffix}`;
            if (!/^\+\d+$/.test(code)) {
                continue;
            }

            const current = bestByIso2.get(iso2);
            // Keep a single prefix per country, preferring the shortest (usually the canonical one).
            if (!current || code.length < current.code.length || (code.length === current.code.length && code < current.code)) {
                bestByIso2.set(iso2, {
                    iso2,
                    country: countryName,
                    code,
                    label: `${iso2} ${code}`
                });
            }
        }
    }

    const prefixes = Array.from(bestByIso2.values());

    prefixes.sort((a, b) => {
        if (a.country < b.country) return -1;
        if (a.country > b.country) return 1;
        return 0;
    });

    return prefixes;
};

const fetchPhonePrefixes = async () => {
    const now = Date.now();
    if (phonePrefixCache.data && now < phonePrefixCache.expiresAt) {
        return phonePrefixCache.data;
    }

    const response = await axios.get('https://restcountries.com/v3.1/all?fields=name,cca2,idd', {
        timeout: 7000
    });

    const normalized = normalizePrefixes(response.data || []);
    if (!normalized.length) {
        throw new Error('No prefixes returned by upstream API');
    }

    phonePrefixCache = {
        data: normalized,
        expiresAt: now + CACHE_TTL_MS
    };

    return normalized;
};

exports.getPhonePrefixes = async (req, res) => {
    try {
        const prefixes = await fetchPhonePrefixes();
        return res.json({ prefixes, source: 'restcountries' });
    } catch (error) {
        return res.json({ prefixes: FALLBACK_PREFIXES, source: 'fallback' });
    }
};

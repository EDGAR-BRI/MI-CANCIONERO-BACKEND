/**
 * Utilidades para trabajar con formato ChordPro
 */

/**
 * Valida si un texto está en formato ChordPro básico
 * @param {string} text - Texto a validar
 * @returns {boolean} - True si parece ser ChordPro válido
 */
function isValidChordPro(text) {
    if (!text || typeof text !== 'string') {
        return false;
    }

    // Verificar que tenga al menos algunos elementos de ChordPro
    const hasChords = /\[[A-G][#b]?[m]?[0-9]?[^[\]]*\]/.test(text);
    const hasDirectives = /\{(title|t|subtitle|st|key|time|tempo|artist|author|composer):[^}]+\}/.test(text);
    const hasSections = /\[(Verse|Chorus|Bridge|Intro|Outro|Pre-Chorus|Interlude)\]/i.test(text);

    return hasChords || hasDirectives || hasSections;
}

/**
 * Extrae los acordes de un texto en formato ChordPro
 * @param {string} chordProText - Texto en formato ChordPro
 * @returns {Array<string>} - Array de acordes únicos encontrados
 */
function extractChords(chordProText) {
    if (!chordProText) return [];

    const chordRegex = /\[([A-G][#b]?[m]?[0-9]?[^\]]*)\]/g;
    const chords = new Set();
    let match;

    while ((match = chordRegex.exec(chordProText)) !== null) {
        const chord = match[1].trim();
        if (chord) {
            chords.add(chord);
        }
    }

    return Array.from(chords);
}

/**
 * Extrae metadata de un texto ChordPro
 * @param {string} chordProText - Texto en formato ChordPro
 * @returns {Object} - Objeto con metadata (title, key, artist, etc.)
 */
function extractMetadata(chordProText) {
    if (!chordProText) return {};

    const metadata = {};
    const directiveRegex = /\{(title|t|subtitle|st|key|time|tempo|artist|author|composer):([^}]+)\}/gi;
    let match;

    while ((match = directiveRegex.exec(chordProText)) !== null) {
        const key = match[1].toLowerCase();
        const value = match[2].trim();

        // Normalizar nombres de directivas
        if (key === 't') metadata.title = value;
        else if (key === 'st') metadata.subtitle = value;
        else if (key === 'artist' || key === 'composer') {
            metadata.author = value;
            metadata[key] = value;
        } else metadata[key] = value;
    }

    return metadata;
}

/**
 * Limpia el texto de formato ChordPro dejando solo la letra
 * @param {string} chordProText - Texto en formato ChordPro
 * @returns {string} - Solo la letra sin acordes ni directivas
 */
function stripChords(chordProText) {
    if (!chordProText) return '';

    return chordProText
        // Remover directivas
        .replace(/\{[^}]+\}/g, '')
        // Remover acordes
        .replace(/\[[^\]]+\]/g, '')
        // Limpiar líneas vacías múltiples
        .replace(/\n{3,}/g, '\n\n')
        .trim();
}

/**
 * Formatea un texto asegurando que tenga la estructura básica de ChordPro
 * @param {string} text - Texto a formatear
 * @param {Object} metadata - Metadata opcional (title, key, etc.)
 * @returns {string} - Texto formateado en ChordPro
 */
function formatAsChordPro(text, metadata = {}) {
    let formatted = '';

    // Agregar metadata si existe
    if (metadata.title) {
        formatted += `{title: ${metadata.title}}\n`;
    }
    if (metadata.key) {
        formatted += `{key: ${metadata.key}}\n`;
    }
    const authorVal = metadata.author || metadata.artist;
    if (authorVal) {
        formatted += `{author: ${authorVal}}\n`;
    }
    if (metadata.tempo) {
        formatted += `{tempo: ${metadata.tempo}}\n`;
    }

    if (formatted) {
        formatted += '\n';
    }

    formatted += text;

    return formatted;
}

/**
 * Valida que los acordes sean válidos musicalmente
 * @param {Array<string>} chords - Array de acordes a validar
 * @returns {Object} - {valid: boolean, invalidChords: Array}
 */
function validateChords(chords) {
    const validChordPattern = /^[A-G][#b]?(m|maj|min|dim|aug|sus|add)?[0-9]?$/;
    const invalidChords = [];

    for (const chord of chords) {
        if (!validChordPattern.test(chord)) {
            invalidChords.push(chord);
        }
    }

    return {
        valid: invalidChords.length === 0,
        invalidChords
    };
}

module.exports = {
    isValidChordPro,
    extractChords,
    extractMetadata,
    stripChords,
    formatAsChordPro,
    validateChords
};

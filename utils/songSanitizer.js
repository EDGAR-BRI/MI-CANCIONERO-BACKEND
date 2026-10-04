/**
 * Utilidad de backend para sanitizar el contenido de canciones litúrgicas en formato ChordPro.
 * Normaliza saltos de línea y une únicamente líneas huérfanas o cortadas accidentalmente
 * (ej. 1 palabra colgante o cortes tras conectores como "que", "de", "el"),
 * respetando versos líricos naturales para evitar desbordes en dispositivos móviles.
 */

function getLyricsWords(line) {
    const lyricsOnly = (line || '').replace(/\[.*?\]/g, '').trim();
    if (!lyricsOnly) return [];
    return lyricsOnly.split(/\s+/).filter(Boolean);
}

function getLyricsText(line) {
    return (line || '').replace(/\[.*?\]/g, '').trim();
}

function isSectionDirective(line) {
    const clean = (line || '').trim();
    return (
        /^\s*\{(?:c|comment|oc|soc|eoc):.*\}\s*$/i.test(clean) ||
        /^\s*\[(?:intro|coro|estrofa|puente|final|outro|interludio|verso|solo|pre-coro).*\]\s*$/i.test(clean) ||
        /^\s*\((?:intro|coro|estrofa|puente|final|outro|interludio|verso|solo|pre-coro).*\)\s*$/i.test(clean)
    );
}

function isTabLine(line) {
    const clean = (line || '').trim();
    return /^[eEaAdDgGbB]\|[-0-9]/.test(clean) || /\|[-0-9]{2,}\|/.test(clean);
}

const DANGLING_CONNECTOR_REGEX = /\b(que|de|en|y|o|el|la|los|las|un|una|al|del|por|con|tan|su|mi|tu|para)$/i;

function sanitizeSongContent(content) {
    if (!content || typeof content !== 'string') return content || '';

    // 1. Normalizar saltos de línea (Windows/Mac) y tabulaciones
    const normalized = content.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\t/g, '  ');

    // 2. Dividir en líneas y procesar por bloques delimitados por líneas en blanco
    const rawLines = normalized.split('\n');
    const sanitizedLines = [];

    let currentBlock = [];

    const flushBlock = () => {
        if (currentBlock.length === 0) return;

        const processed = [];
        for (let i = 0; i < currentBlock.length; i++) {
            const line = currentBlock[i].trim();
            if (!line) continue;

            if (isSectionDirective(line) || isTabLine(line)) {
                processed.push(line);
                continue;
            }

            const words = getLyricsWords(line);

            // Si es una línea solo de acordes (instrumental), no unir con letra
            if (words.length === 0) {
                processed.push(line);
                continue;
            }

            const lyricsText = getLyricsText(line);
            const prevLine = processed.length > 0 ? processed[processed.length - 1] : null;
            const canMergeWithPrev = Boolean(prevLine && !isSectionDirective(prevLine) && !isTabLine(prevLine));

            if (canMergeWithPrev && prevLine) {
                const prevLyricsText = getLyricsText(prevLine);
                const prevWords = getLyricsWords(prevLine);
                const combinedLength = prevLyricsText.length + 1 + lyricsText.length;
                const combinedWords = prevWords.length + words.length;

                // Solo unir si:
                // 1) La línea anterior terminaba en conector colgante (ej. '...el aire que' -> 'respiro')
                // 2) La línea actual es huérfana (1 palabra, o 2 palabras sin puntuación previa)
                const prevEndsWithConnector = DANGLING_CONNECTOR_REGEX.test(prevLyricsText);
                const isOrphan = (words.length === 1) || (words.length === 2 && !/[,.:;!?]$/.test(prevLyricsText));

                // Restricción crítica: no unir si la suma excede el ancho seguro móvil (~40-42 caracteres o > 9 palabras)
                if ((prevEndsWithConnector || isOrphan) && combinedLength <= 42 && combinedWords <= 9) {
                    processed[processed.length - 1] = prevLine + ' ' + line;
                    continue;
                }
            }

            processed.push(line);
        }

        sanitizedLines.push(...processed);
        currentBlock = [];
    };

    for (const line of rawLines) {
        const trimmed = line.trim();
        if (!trimmed) {
            flushBlock();
            if (sanitizedLines.length > 0 && sanitizedLines[sanitizedLines.length - 1] !== '') {
                sanitizedLines.push('');
            }
        } else {
            currentBlock.push(trimmed);
        }
    }
    flushBlock();

    // Eliminar líneas vacías al inicio y al final
    while (sanitizedLines.length > 0 && sanitizedLines[0] === '') sanitizedLines.shift();
    while (sanitizedLines.length > 0 && sanitizedLines[sanitizedLines.length - 1] === '') sanitizedLines.pop();

    return sanitizedLines.join('\n');
}

/**
 * Normaliza el título de una canción para comparaciones estrictas y detección de duplicados.
 * Elimina acentos/diacríticos, caracteres invisibles (soft-hyphens), signos de puntuación
 * y unifica espacios en blanco y mayúsculas/minúsculas.
 * Ej: "¡A tí, Señor te ofrezco el pan!" -> "a ti senor te ofrezco el pan"
 */
function normalizeSongTitle(str) {
    if (!str || typeof str !== 'string') return '';
    return str
        .replace(/\u00ad/g, '')
        .normalize('NFD')
        .replace(/[\u0300-\u036f]/g, '')
        .replace(/[^a-zA-Z0-9\s]/g, '')
        .trim()
        .toLowerCase()
        .replace(/\s+/g, ' ');
}

module.exports = {
    getLyricsWords,
    getLyricsText,
    isSectionDirective,
    isTabLine,
    sanitizeSongContent,
    normalizeSongTitle
};


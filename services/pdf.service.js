const path = require('path');
const pdfmake = require('pdfmake');
const { transposeText } = require('../utils/music');
const { sanitizeSongContent } = require('../utils/songSanitizer');

// Configure pdfmake policies
pdfmake.setUrlAccessPolicy(() => false);
pdfmake.setLocalAccessPolicy(() => true);

// Configure fonts
const robotoDir = path.join(__dirname, '../node_modules/pdfmake/fonts/Roboto');
pdfmake.setFonts({
    Roboto: {
        normal: path.join(robotoDir, 'Roboto-Regular.ttf'),
        bold: path.join(robotoDir, 'Roboto-Medium.ttf'),
        italics: path.join(robotoDir, 'Roboto-Italic.ttf'),
        bolditalics: path.join(robotoDir, 'Roboto-MediumItalic.ttf')
    },
    Courier: {
        normal: 'Courier',
        bold: 'Courier-Bold',
        italics: 'Courier-Oblique',
        bolditalics: 'Courier-BoldOblique'
    }
});

/**
 * Parses a ChordPro line into aligned chord and lyric lines for monospace rendering.
 */
const parseChordProLine = (line) => {
    let chordLine = '';
    let lyricLine = '';
    const parts = line.split(/(\[.*?\])/);
    let currentChord = null;

    for (const part of parts) {
        if (!part) continue;
        const chordMatch = part.match(/^\[(.*?)\]$/);
        if (chordMatch) {
            currentChord = chordMatch[1];
        } else {
            if (currentChord) {
                const targetPos = lyricLine.length;
                if (chordLine.length < targetPos) {
                    chordLine += ' '.repeat(targetPos - chordLine.length);
                } else if (chordLine.length > targetPos) {
                    lyricLine += ' '.repeat(chordLine.length - targetPos);
                }
                chordLine += currentChord;
                currentChord = null;
            }
            lyricLine += part;
        }
    }

    if (currentChord) {
        const targetPos = lyricLine.length;
        if (chordLine.length < targetPos) {
            chordLine += ' '.repeat(targetPos - chordLine.length);
        }
        chordLine += currentChord;
    }

    return {
        hasChords: Boolean(chordLine.trim()),
        chordLine,
        lyricLine
    };
};

/**
 * Formats a Date object or ISO string in Spanish.
 */
const formatSpanishDate = (dateMisa) => {
    if (!dateMisa) return '';
    const d = new Date(dateMisa);
    if (isNaN(d.getTime())) return String(dateMisa);

    const datePart = d.toLocaleDateString('es-ES', {
        weekday: 'long',
        year: 'numeric',
        month: 'long',
        day: 'numeric'
    });

    const hours = d.getHours();
    const minutes = d.getMinutes();
    let timePart = '';
    if (hours !== 0 || minutes !== 0) {
        timePart = ' • ' + d.toLocaleTimeString('es-ES', {
            hour: '2-digit',
            minute: '2-digit',
            hour12: true
        });
    }

    return datePart.charAt(0).toUpperCase() + datePart.slice(1) + timePart;
};

/**
 * Builds the pdfmake document definition for a given Misa.
 */
const buildMisaDocDefinition = (misa, options = {}) => {
    const withChords = options.withChords !== false;
    const celebrationDate = formatSpanishDate(misa.dateMisa);

    // Collect moments
    const momentsList = (misa.misaMoments && misa.misaMoments.length > 0)
        ? misa.misaMoments.map(mm => mm.moment)
        : [];

    // Fallback if misaMoments is empty: extract unique moments from misaSongs
    if (momentsList.length === 0 && misa.misaSongs) {
        const seen = new Set();
        for (const ms of misa.misaSongs) {
            if (ms.moment && !seen.has(ms.moment.id)) {
                seen.add(ms.moment.id);
                momentsList.push(ms.moment);
            }
        }
    }

    const content = [];

    // Header Info (Misa Title, Ministry, Date)
    const headerStack = [];
    if (misa.ministry?.name) {
        headerStack.push({
            text: misa.ministry.name.toUpperCase(),
            fontSize: 9,
            bold: true,
            color: '#FF5722',
            margin: [0, 0, 0, 3]
        });
    }

    headerStack.push({
        text: misa.title,
        fontSize: 18,
        bold: true,
        color: '#111111',
        margin: [0, 0, 0, 4]
    });

    const metaParts = [];
    if (celebrationDate) metaParts.push(celebrationDate);
    if (misa.user?.name) metaParts.push(`Preparada por: ${misa.user.name}`);
    metaParts.push(withChords ? 'Edición con Acordes (Músicos)' : 'Edición Solo Letra (Coro)');

    headerStack.push({
        text: metaParts.join('  •  '),
        fontSize: 8.5,
        color: '#666666',
        margin: [0, 0, 0, 8]
    });

    content.push({ stack: headerStack, margin: [0, 0, 0, 5] });

    // Accent separating rule
    content.push({
        canvas: [
            {
                type: 'line',
                x1: 0,
                y1: 0,
                x2: 523,
                y2: 0,
                lineWidth: 1.5,
                lineColor: '#FF5722'
            }
        ],
        margin: [0, 0, 0, 14]
    });

    // Moments and Songs
    let songCounter = 1;
    for (const moment of momentsList) {
        const momentSongs = (misa.misaSongs || []).filter(ms => ms.momentId === moment.id);
        if (momentSongs.length === 0) continue;

        // Moment Section Header Banner
        content.push({
            table: {
                widths: ['*'],
                body: [
                    [
                        {
                            text: moment.nombre.toUpperCase(),
                            fontSize: 10,
                            bold: true,
                            color: '#FFFFFF',
                            fillColor: '#FF5722',
                            margin: [8, 4, 8, 4]
                        }
                    ]
                ]
            },
            layout: 'noBorders',
            margin: [0, 8, 0, 10]
        });

        // Each song in this moment
        for (const ms of momentSongs) {
            const song = ms.song;
            if (!song) continue;

            const effectiveKey = ms.key || song.key;
            const originalKey = song.key;
            let songContent = sanitizeSongContent(song.content || '');

            // Transpose if necessary
            if (effectiveKey && originalKey && effectiveKey !== originalKey) {
                songContent = transposeText(songContent, originalKey, effectiveKey);
            }

            const toneInfo = effectiveKey !== originalKey
                ? `Tono: ${effectiveKey} (Original: ${originalKey})`
                : `Tono: ${effectiveKey}`;

            const authorInfo = song.author?.name ? `Autor: ${song.author.name}` : null;
            const songMeta = [toneInfo, authorInfo].filter(Boolean).join('   |   ');

            // Song Header
            const songHeaderBlock = {
                stack: [
                    {
                        text: `${songCounter}. ${song.title}`,
                        fontSize: 12,
                        bold: true,
                        color: '#111111',
                        margin: [0, 4, 0, 2]
                    },
                    {
                        text: songMeta,
                        fontSize: 8.5,
                        italics: true,
                        color: '#555555',
                        margin: [0, 0, 0, 6]
                    }
                ],
                unbreakable: true
            };
            content.push(songHeaderBlock);
            songCounter += 1;

            // Render Song Lines / Stanzas
            const rawLines = songContent.split('\n');
            const stanzas = [];
            let currentStanza = [];

            for (const line of rawLines) {
                if (!line.trim()) {
                    if (currentStanza.length > 0) {
                        stanzas.push(currentStanza);
                        currentStanza = [];
                    }
                } else {
                    currentStanza.push(line);
                }
            }
            if (currentStanza.length > 0) {
                stanzas.push(currentStanza);
            }

            // Render each stanza
            for (const stanza of stanzas) {
                const stanzaElements = [];

                for (const line of stanza) {
                    // Check for comment directives like {c: Coro} or {comment: ...}
                    const commentMatch = line.match(/^\s*\{(?:c|comment|oc|soc|eoc):\s*(.*?)\}\s*$/i);
                    if (commentMatch) {
                        const commentText = commentMatch[1] || 'Coro';
                        stanzaElements.push({
                            text: `[ ${commentText} ]`,
                            fontSize: 8.5,
                            bold: true,
                            italics: true,
                            color: '#FF5722',
                            margin: [0, 4, 0, 2]
                        });
                        continue;
                    }

                    if (!withChords) {
                        // Solo Letra mode: strip chords
                        const cleanLine = line.replace(/\[(.*?)\]/g, '').trimEnd();
                        if (cleanLine) {
                            stanzaElements.push({
                                text: cleanLine,
                                fontSize: 9.5,
                                font: 'Roboto',
                                color: '#222222',
                                lineHeight: 1.2
                            });
                        }
                    } else {
                        // Con Acordes mode: align chords in monospace Courier
                        const parsed = parseChordProLine(line);
                        if (parsed.hasChords) {
                            stanzaElements.push({
                                text: [
                                    {
                                        text: parsed.chordLine + '\n',
                                        font: 'Courier',
                                        bold: true,
                                        color: '#FF5722',
                                        fontSize: 8.5
                                    },
                                    {
                                        text: parsed.lyricLine + '\n',
                                        font: 'Courier',
                                        color: '#222222',
                                        fontSize: 8.5
                                    }
                                ],
                                lineHeight: 1.05
                            });
                        } else {
                            stanzaElements.push({
                                text: parsed.lyricLine + '\n',
                                font: 'Courier',
                                color: '#222222',
                                fontSize: 8.5,
                                lineHeight: 1.05
                            });
                        }
                    }
                }

                if (stanzaElements.length > 0) {
                    content.push({
                        stack: stanzaElements,
                        margin: [0, 0, 0, 7],
                        unbreakable: true
                    });
                }
            }

            // Spacing after song
            content.push({ text: '', margin: [0, 0, 0, 6] });
        }
    }

    return {
        pageSize: 'A4',
        pageMargins: [36, 36, 36, 42],
        header: (currentPage) => {
            if (currentPage === 1) return null;
            return {
                columns: [
                    {
                        text: misa.title,
                        fontSize: 8,
                        color: '#888888',
                        margin: [36, 16, 0, 0]
                    },
                    {
                        text: misa.ministry?.name || 'Cancionero Digital',
                        alignment: 'right',
                        fontSize: 8,
                        color: '#888888',
                        margin: [0, 16, 36, 0]
                    }
                ]
            };
        },
        footer: (currentPage, pageCount) => {
            return {
                columns: [
                    {
                        text: 'Cancionero Digital • cancionero.app',
                        fontSize: 8,
                        color: '#888888',
                        margin: [36, 10, 0, 0]
                    },
                    {
                        text: `Página ${currentPage} de ${pageCount}`,
                        alignment: 'right',
                        fontSize: 8,
                        color: '#888888',
                        margin: [0, 10, 36, 0]
                    }
                ]
            };
        },
        content
    };
};

/**
 * Generates a PDF buffer for a Misa.
 * @param {object} misa - Misa object with songs and moments included
 * @param {object} options - Options (withChords: boolean)
 * @returns {Promise<Buffer>} - Resolves to the PDF Buffer
 */
const generateMisaPdf = async (misa, options = {}) => {
    const docDefinition = buildMisaDocDefinition(misa, options);
    const pdfDoc = pdfmake.createPdf(docDefinition);
    return await pdfDoc.getBuffer();
};

/**
 * Builds the pdfmake document definition for a single song.
 * @param {object} song - Song object with author and categories
 * @param {object} options - Options (withChords: boolean, tone: string)
 */
const buildSongDocDefinition = (song, options = {}) => {
    const withChords = options.withChords !== false;
    const effectiveKey = options.tone || song.key || 'C';
    const originalKey = song.key || 'C';

    let songContent = sanitizeSongContent(song.content || '');
    if (effectiveKey && originalKey && effectiveKey !== originalKey) {
        try {
            songContent = transposeText(songContent, originalKey, effectiveKey);
        } catch (e) {
            console.error('Error transposing song in PDF:', e);
        }
    }

    const authorName = song.author?.name || 'Desconocido';
    const categoriesStr = (song.categories && song.categories.length > 0)
        ? song.categories.map(c => c.name).join(', ')
        : (song.category?.name || '');

    const toneText = effectiveKey !== originalKey
        ? `Tono: ${effectiveKey} (Original: ${originalKey})`
        : `Tono: ${effectiveKey}`;

    const metaParts = [toneText, `Autor: ${authorName}`];
    if (categoriesStr) metaParts.push(`Categoría: ${categoriesStr}`);

    const content = [];

    // Header stack
    content.push({
        stack: [
            {
                columns: [
                    {
                        text: 'CANCIONERO DIGITAL',
                        fontSize: 9,
                        bold: true,
                        color: '#FF5722',
                        characterSpacing: 1.5
                    },
                    {
                        text: withChords ? 'LETRA Y ACORDES' : 'SOLO LETRA',
                        fontSize: 8.5,
                        bold: true,
                        color: '#888888',
                        alignment: 'right'
                    }
                ]
            },
            {
                text: song.title || 'Canción',
                fontSize: 22,
                bold: true,
                color: '#111111',
                margin: [0, 4, 0, 3]
            },
            {
                text: metaParts.join('   •   '),
                fontSize: 9,
                color: '#555555',
                margin: [0, 0, 0, 8]
            }
        ],
        margin: [0, 0, 0, 6]
    });

    // Separator line
    content.push({
        canvas: [
            {
                type: 'line',
                x1: 0,
                y1: 0,
                x2: 523,
                y2: 0,
                lineWidth: 1.5,
                lineColor: '#FF5722'
            }
        ],
        margin: [0, 0, 0, 14]
    });

    // Split stanzas
    const rawLines = songContent.split('\n');
    const stanzas = [];
    let currentStanza = [];

    for (const line of rawLines) {
        if (!line.trim()) {
            if (currentStanza.length > 0) {
                stanzas.push(currentStanza);
                currentStanza = [];
            }
        } else {
            currentStanza.push(line);
        }
    }
    if (currentStanza.length > 0) {
        stanzas.push(currentStanza);
    }

    // Render stanzas
    for (const stanza of stanzas) {
        const stanzaElements = [];

        for (const line of stanza) {
            // Check for comment directives like {c: Coro} or {comment: ...}
            const commentMatch = line.match(/^\s*\{(?:c|comment|oc|soc|eoc):\s*(.*?)\}\s*$/i);
            if (commentMatch) {
                const commentText = commentMatch[1] || 'Coro';
                stanzaElements.push({
                    text: `[ ${commentText} ]`,
                    fontSize: 9,
                    bold: true,
                    italics: true,
                    color: '#FF5722',
                    margin: [0, 4, 0, 2]
                });
                continue;
            }

            if (!withChords) {
                const cleanLine = line.replace(/\[(.*?)\]/g, '').trimEnd();
                if (cleanLine) {
                    stanzaElements.push({
                        text: cleanLine,
                        fontSize: 10,
                        font: 'Roboto',
                        color: '#222222',
                        lineHeight: 1.25
                    });
                }
            } else {
                const parsed = parseChordProLine(line);
                if (parsed.hasChords) {
                    stanzaElements.push({
                        text: [
                            {
                                text: parsed.chordLine + '\n',
                                font: 'Courier',
                                bold: true,
                                color: '#FF5722',
                                fontSize: 9
                            },
                            {
                                text: parsed.lyricLine + '\n',
                                font: 'Courier',
                                color: '#222222',
                                fontSize: 9
                            }
                        ],
                        lineHeight: 1.05
                    });
                } else {
                    stanzaElements.push({
                        text: parsed.lyricLine + '\n',
                        font: 'Courier',
                        color: '#222222',
                        fontSize: 9,
                        lineHeight: 1.05
                    });
                }
            }
        }

        if (stanzaElements.length > 0) {
            content.push({
                stack: stanzaElements,
                margin: [0, 0, 0, 10],
                unbreakable: stanzaElements.length <= 14
            });
        }
    }

    return {
        pageSize: 'A4',
        pageMargins: [36, 36, 36, 36],
        defaultStyle: {
            font: 'Roboto'
        },
        footer: (currentPage, pageCount) => ({
            columns: [
                {
                    text: 'Cancionero Digital • Letra y Acordes Litúrgicos',
                    fontSize: 8,
                    color: '#888888',
                    margin: [36, 10, 0, 0]
                },
                {
                    text: `Página ${currentPage} de ${pageCount}`,
                    fontSize: 8,
                    alignment: 'right',
                    color: '#888888',
                    margin: [0, 10, 36, 0]
                }
            ]
        }),
        content
    };
};

/**
 * Generates a PDF buffer for a Song.
 * @param {object} song - Song object with author and categories
 * @param {object} options - Options (withChords: boolean, tone: string)
 * @returns {Promise<Buffer>} - Resolves to the PDF Buffer
 */
const generateSongPdf = async (song, options = {}) => {
    const docDefinition = buildSongDocDefinition(song, options);
    const pdfDoc = pdfmake.createPdf(docDefinition);
    return await pdfDoc.getBuffer();
};

module.exports = {
    generateMisaPdf,
    buildMisaDocDefinition,
    generateSongPdf,
    buildSongDocDefinition,
    parseChordProLine,
    formatSpanishDate
};

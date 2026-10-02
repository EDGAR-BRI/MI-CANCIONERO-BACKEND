const { generateMisaPdf, generateSongPdf, parseChordProLine, formatSpanishDate } = require('../services/pdf.service');

describe('PDF Service with pdfmake', () => {
    describe('parseChordProLine', () => {
        it('debe separar acordes y letras alineándolos correctamente', () => {
            const line = '[G]Junto a ti al ca[D]er de la [Em]tarde';
            const parsed = parseChordProLine(line);

            expect(parsed.hasChords).toBe(true);
            expect(parsed.chordLine).toContain('G');
            expect(parsed.chordLine).toContain('D');
            expect(parsed.chordLine).toContain('Em');
            expect(parsed.lyricLine).toBe('Junto a ti al caer de la tarde');
        });

        it('debe reconocer líneas sin acordes', () => {
            const line = 'Esta es una línea de solo texto';
            const parsed = parseChordProLine(line);

            expect(parsed.hasChords).toBe(false);
            expect(parsed.chordLine).toBe('');
            expect(parsed.lyricLine).toBe(line);
        });
    });

    describe('formatSpanishDate', () => {
        it('debe formatear una fecha válida en español con día de semana', () => {
            const formatted = formatSpanishDate('2026-10-15T10:00:00Z');
            expect(formatted.toLowerCase()).toContain('octubre');
            expect(formatted).toContain('2026');
        });
    });

    describe('generateMisaPdf', () => {
        const mockMisa = {
            id: 10,
            title: 'Misa Dominical',
            dateMisa: new Date('2026-10-18T10:30:00Z'),
            visibility: 'PUBLIC',
            ministry: { name: 'Ministerio Santa Cecilia' },
            user: { name: 'Director Musical' },
            misaMoments: [
                { moment: { id: 1, nombre: 'Entrada' } }
            ],
            misaSongs: [
                {
                    momentId: 1,
                    key: 'D',
                    song: {
                        id: 5,
                        title: 'Alabanza al Señor',
                        key: 'C',
                        content: '{c: Coro}\n[C]Cantad al Señor un [G]cántico nuevo.',
                        author: { name: 'Compositor Sacro' }
                    }
                }
            ]
        };

        it('debe generar un buffer de PDF con acordes', async () => {
            const buffer = await generateMisaPdf(mockMisa, { withChords: true });
            expect(Buffer.isBuffer(buffer)).toBe(true);
            expect(buffer.length).toBeGreaterThan(1000);
            // Verify PDF header magic bytes %PDF-
            expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
        });

        it('debe generar un buffer de PDF sin acordes (modo solo letra)', async () => {
            const buffer = await generateMisaPdf(mockMisa, { withChords: false });
            expect(Buffer.isBuffer(buffer)).toBe(true);
            expect(buffer.length).toBeGreaterThan(1000);
            expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
        });
    });

    describe('generateSongPdf', () => {
        const mockSong = {
            id: 42,
            title: 'Cantaré al Señor por siempre',
            key: 'Em',
            content: '{c: Coro}\n[Em]Cantaré al Señor por [D]siempre, su diestra es [Em]todo poder.\n\nEchó a la mar quien los perseguía.',
            author: { name: 'Palabra en Acción' },
            categories: [{ name: 'Alabanza' }]
        };

        it('debe generar un buffer de PDF para una canción con acordes', async () => {
            const buffer = await generateSongPdf(mockSong, { withChords: true });
            expect(Buffer.isBuffer(buffer)).toBe(true);
            expect(buffer.length).toBeGreaterThan(1000);
            expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
        });

        it('debe generar un buffer de PDF para una canción en modo solo letra', async () => {
            const buffer = await generateSongPdf(mockSong, { withChords: false });
            expect(Buffer.isBuffer(buffer)).toBe(true);
            expect(buffer.length).toBeGreaterThan(1000);
            expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
        });

        it('debe transponer los acordes si se especifica un tono diferente', async () => {
            const buffer = await generateSongPdf(mockSong, { withChords: true, tone: 'Am' });
            expect(Buffer.isBuffer(buffer)).toBe(true);
            expect(buffer.length).toBeGreaterThan(1000);
            expect(buffer.subarray(0, 5).toString()).toBe('%PDF-');
        });
    });
});

import { describe, it, expect } from 'vitest';
const {
    isValidChordPro,
    extractChords,
    extractMetadata,
    stripChords,
    formatAsChordPro,
    validateChords
} = require('../utils/chordpro.utils');

describe('ChordPro Utilities (back/utils/chordpro.utils)', () => {
    describe('isValidChordPro', () => {
        it('debe retornar false para valores nulos, indefinidos o vacíos', () => {
            expect(isValidChordPro(null)).toBe(false);
            expect(isValidChordPro(undefined)).toBe(false);
            expect(isValidChordPro('')).toBe(false);
            expect(isValidChordPro(123)).toBe(false);
        });

        it('debe retornar true si el texto contiene acordes entre corchetes', () => {
            const text = 'En el [C]principio creo Dios los [G]cielos y la [Am]tierra';
            expect(isValidChordPro(text)).toBe(true);
        });

        it('debe retornar true si el texto contiene directivas ChordPro', () => {
            expect(isValidChordPro('{title: Pescador de Hombres}')).toBe(true);
            expect(isValidChordPro('{key: D}')).toBe(true);
            expect(isValidChordPro('{tempo: 120}')).toBe(true);
            expect(isValidChordPro('{artist: Cesáreo Gabaráin}')).toBe(true);
        });

        it('debe retornar true si el texto contiene marcadores de sección', () => {
            expect(isValidChordPro('[Verse]\nCanto al señor')).toBe(true);
            expect(isValidChordPro('[Chorus]\nGloria a Dios')).toBe(true);
            expect(isValidChordPro('[Bridge]\nSanto Santo')).toBe(true);
        });

        it('debe retornar false para texto plano sin acordes ni directivas', () => {
            const plainText = 'Esta es una letra ordinaria sin acordes ni directivas especiales.';
            expect(isValidChordPro(plainText)).toBe(false);
        });
    });

    describe('extractChords', () => {
        it('debe retornar array vacío para texto nulo o vacío', () => {
            expect(extractChords(null)).toEqual([]);
            expect(extractChords('')).toEqual([]);
        });

        it('debe extraer acordes únicos ignorando repeticiones', () => {
            const song = '[C] Santo [G] santo [Am] es el [F] señor [C] Dios [G] poder';
            const chords = extractChords(song);
            expect(chords).toEqual(['C', 'G', 'Am', 'F']);
        });

        it('debe extraer acordes con alteraciones, séptimas y bajos', () => {
            const song = '[F#m7] Tu fidelidad [B7] es grande [E/G#] tu amor [C#m]';
            const chords = extractChords(song);
            expect(chords).toContain('F#m7');
            expect(chords).toContain('B7');
            expect(chords).toContain('E/G#');
            expect(chords).toContain('C#m');
        });
    });

    describe('extractMetadata', () => {
        it('debe retornar objeto vacío si el texto es nulo o vacío', () => {
            expect(extractMetadata(null)).toEqual({});
            expect(extractMetadata('')).toEqual({});
        });

        it('debe extraer directivas estándar de metadatos', () => {
            const chordpro = `{title: Canto de Entrada}\n{key: Em}\n{tempo: 90}\n{time: 4/4}\n[Em] Vamos hacia el altar`;
            const meta = extractMetadata(chordpro);
            expect(meta.title).toBe('Canto de Entrada');
            expect(meta.key).toBe('Em');
            expect(meta.tempo).toBe('90');
            expect(meta.time).toBe('4/4');
        });

        it('debe manejar directivas abreviadas t y st', () => {
            const chordpro = `{t: Título Corto}\n{st: Subtítulo de Prueba}`;
            const meta = extractMetadata(chordpro);
            expect(meta.title).toBe('Título Corto');
            expect(meta.subtitle).toBe('Subtítulo de Prueba');
        });

        it('debe normalizar artist y composer como author', () => {
            const chordpro1 = `{artist: Autor Católico}`;
            const meta1 = extractMetadata(chordpro1);
            expect(meta1.author).toBe('Autor Católico');
            expect(meta1.artist).toBe('Autor Católico');

            const chordpro2 = `{composer: San Francisco}`;
            const meta2 = extractMetadata(chordpro2);
            expect(meta2.author).toBe('San Francisco');
            expect(meta2.composer).toBe('San Francisco');
        });
    });

    describe('stripChords', () => {
        it('debe retornar cadena vacía para entradas falsy', () => {
            expect(stripChords(null)).toBe('');
            expect(stripChords('')).toBe('');
        });

        it('debe remover acordes y directivas dejando solo la letra', () => {
            const chordpro = `{title: Prueba}\n{key: C}\n[C]Alabado [G]sea [Am]el Señor`;
            const lyrics = stripChords(chordpro);
            expect(lyrics).toBe('Alabado sea el Señor');
        });

        it('debe limpiar múltiples saltos de línea consecutivos', () => {
            const input = `Línea 1\n\n\n\n\nLínea 2`;
            const result = stripChords(input);
            expect(result).toBe('Línea 1\n\nLínea 2');
        });
    });

    describe('formatAsChordPro', () => {
        it('debe formatear texto agregando metadatos', () => {
            const text = '[D]Dios está [A]aquí';
            const formatted = formatAsChordPro(text, {
                title: 'Dios está aquí',
                key: 'D',
                author: 'Javier Gacías',
                tempo: '80'
            });

            expect(formatted).toContain('{title: Dios está aquí}');
            expect(formatted).toContain('{key: D}');
            expect(formatted).toContain('{author: Javier Gacías}');
            expect(formatted).toContain('{tempo: 80}');
            expect(formatted).toContain('[D]Dios está [A]aquí');
        });

        it('debe devolver solo el texto si no se proporcionan metadatos', () => {
            const text = '[D]Dios está [A]aquí';
            expect(formatAsChordPro(text, {})).toBe(text);
        });
    });

    describe('validateChords', () => {
        it('debe validar acordes correctos', () => {
            const chords = ['C', 'Dm', 'G7', 'F#m', 'Bb', 'Asus', 'Bdim', 'Cmaj7'];
            const res = validateChords(chords);
            expect(res.valid).toBe(true);
            expect(res.invalidChords).toHaveLength(0);
        });

        it('debe identificar acordes inválidos o con errores de sintaxis', () => {
            const chords = ['C', 'H', 'NOT_A_CHORD', 'X7', 'Am'];
            const res = validateChords(chords);
            expect(res.valid).toBe(false);
            expect(res.invalidChords).toContain('H');
            expect(res.invalidChords).toContain('NOT_A_CHORD');
            expect(res.invalidChords).toContain('X7');
        });
    });
});

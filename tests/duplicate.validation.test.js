import { describe, it, expect } from 'vitest';
const { normalizeSongTitle } = require('../utils/songSanitizer');

describe('Anti-Duplicate Title Normalization', () => {
    it('normalizes accents, diacritics and casing', () => {
        expect(normalizeSongTitle('Tu Fidelidad')).toBe('tu fidelidad');
        expect(normalizeSongTitle('tu fidelidad')).toBe('tu fidelidad');
        expect(normalizeSongTitle('TU FIDELIDAD')).toBe('tu fidelidad');
        expect(normalizeSongTitle('Tú Fidelidád')).toBe('tu fidelidad');
    });

    it('removes punctuation and symbols', () => {
        expect(normalizeSongTitle('¡A tí, Señor te ofrezco el pan!')).toBe('a ti senor te ofrezco el pan');
        expect(normalizeSongTitle('¿A quién iré Señor?')).toBe('a quien ire senor');
        expect(normalizeSongTitle('Abba Padre (Coro Siquem)')).toBe('abba padre coro siquem');
    });

    it('strips invisible soft-hyphens and excessive spaces', () => {
        const withSoftHyphen = 'Dios está aquí\u00ad';
        expect(normalizeSongTitle(withSoftHyphen)).toBe('dios esta aqui');
        expect(normalizeSongTitle('   Cantaré    al   Señor  ')).toBe('cantare al senor');
    });

    it('identifies identical normalized titles from variations', () => {
        const title1 = normalizeSongTitle('A ti, Señor');
        const title2 = normalizeSongTitle('A tí Señor');
        const title3 = normalizeSongTitle('  a ti senor  ');
        expect(title1).toBe(title2);
        expect(title2).toBe(title3);
    });
});

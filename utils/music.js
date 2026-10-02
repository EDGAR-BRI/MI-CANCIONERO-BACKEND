const NOTES = ['C', 'C#', 'D', 'D#', 'E', 'F', 'F#', 'G', 'G#', 'A', 'A#', 'B'];

const normalizeNote = (note) => {
    const map = {
        'Db': 'C#', 'Eb': 'D#', 'Gb': 'F#', 'Ab': 'G#', 'Bb': 'A#',
        'Cb': 'B', 'Fb': 'E', 'E#': 'F', 'B#': 'C'
    };
    return map[note] || note;
};

const getSemidistance = (note1, note2) => {
    const n1 = normalizeNote(note1);
    const n2 = normalizeNote(note2);
    const i1 = NOTES.indexOf(n1);
    const i2 = NOTES.indexOf(n2);
    if (i1 === -1 || i2 === -1) return 0;
    return i2 - i1;
};

const transposeChord = (chord, semitones) => {
    if (!chord) return chord;

    const match = chord.match(/^([A-G][#b]?)(.*)$/);
    if (!match) return chord;

    let [_, root, suffix] = match;
    root = normalizeNote(root);

    const rootIndex = NOTES.indexOf(root);
    if (rootIndex === -1) return chord;

    let newIndex = (rootIndex + semitones) % 12;
    if (newIndex < 0) newIndex += 12;

    const newRoot = NOTES[newIndex];

    if (suffix.includes('/')) {
        const parts = suffix.split('/');
        const bass = parts[parts.length - 1];
        const bassMatch = bass.match(/^([A-G][#b]?)$/);

        if (bassMatch) {
            const bassRoot = normalizeNote(bassMatch[1]);
            const bassIndex = NOTES.indexOf(bassRoot);
            if (bassIndex !== -1) {
                let newBassIndex = (bassIndex + semitones) % 12;
                if (newBassIndex < 0) newBassIndex += 12;
                const newBass = NOTES[newBassIndex];
                suffix = suffix.substring(0, suffix.lastIndexOf('/')) + '/' + newBass;
            }
        }
    }

    return newRoot + suffix;
};

const transposeText = (text, fromKey, toKey) => {
    if (!text || !fromKey || !toKey) return text || '';
    const semitones = getSemidistance(fromKey, toKey);
    if (semitones === 0) return text;

    return text.replace(/\[(.*?)\]/g, (match, chord) => {
        return `[${transposeChord(chord, semitones)}]`;
    });
};

module.exports = {
    NOTES,
    normalizeNote,
    getSemidistance,
    transposeChord,
    transposeText
};

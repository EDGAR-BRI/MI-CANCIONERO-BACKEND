/**
 * externalSongs.service.js
 * 
 * Servicio para buscar y extraer canciones de fuentes externas:
 * 1. Recursos Católicos (recursoscatolicos.com.ar/cancionero)
 * 2. LaCuerda.net (acordes.lacuerda.net)
 * 
 * Convierte acordes y letras a formato estándar ChordPro con notación anglosajona
 * y enriquece estrofas y categorías litúrgicas con Api-IA.
 */

const https = require('https');
const http = require('http');
const { sanitizeSongContent } = require('../utils/songSanitizer');

const LATIN_TO_ANGLO = {
  'DO': 'C',
  'RE': 'D',
  'MI': 'E',
  'FA': 'F',
  'SOL': 'G',
  'LA': 'A',
  'SI': 'B'
};

const LATIN_ROOTS_REGEX = /^(DO|RE|MI|FA|SOL|LA|SI)(#|b)?(.*)$/i;
const ANGLO_ROOTS_REGEX = /^([A-G])(#|b)?(.*)$/;
const CHORD_SUFFIX_REGEX = /^(m|min|maj|maj7|M7|7|9|6|11|13|4|2|5|sus|sus2|sus4|dim|aug|\+|\-|add9|add2|\([^\)]+\))*$/i;

function fetchUrl(url, timeoutMs = 8000) {
  return new Promise((resolve, reject) => {
    const isHttps = url.startsWith('https');
    const client = isHttps ? https : http;
    const req = client.get(
      url,
      {
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'
        }
      },
      (res) => {
        if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
          let nextUrl = res.headers.location;
          if (nextUrl.startsWith('/')) {
            const urlObj = new URL(url);
            nextUrl = `${urlObj.origin}${nextUrl}`;
          }
          return fetchUrl(nextUrl, timeoutMs).then(resolve).catch(reject);
        }
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }
    );
    req.on('error', reject);
    req.setTimeout(timeoutMs, () => {
      req.destroy();
      reject(new Error(`Timeout fetching ${url}`));
    });
  });
}

function isValidSingleChord(token) {
  if (!token) return false;
  if (token.includes('/')) {
    const parts = token.split('/');
    if (parts.length !== 2) return false;
    return isValidSingleChord(parts[0]) && isValidSingleChord(parts[1]);
  }

  const latinMatch = token.match(LATIN_ROOTS_REGEX);
  if (latinMatch && CHORD_SUFFIX_REGEX.test(latinMatch[3])) return true;

  const angloMatch = token.match(ANGLO_ROOTS_REGEX);
  if (angloMatch && CHORD_SUFFIX_REGEX.test(angloMatch[3])) return true;

  return false;
}

function normalizeChord(chordStr) {
  if (!chordStr) return '';
  let clean = chordStr.trim().replace(/\s+/g, '');

  if (clean.includes('/')) {
    const parts = clean.split('/');
    return parts.map(p => normalizeChord(p)).join('/');
  }

  const latinMatch = clean.match(LATIN_ROOTS_REGEX);
  if (latinMatch && CHORD_SUFFIX_REGEX.test(latinMatch[3])) {
    const root = latinMatch[1].toUpperCase();
    const accidental = latinMatch[2] || '';
    const suffix = latinMatch[3] || '';
    const angloRoot = LATIN_TO_ANGLO[root];
    if (angloRoot) {
      return angloRoot + accidental + suffix;
    }
  }

  const angloMatch = clean.match(ANGLO_ROOTS_REGEX);
  if (angloMatch && CHORD_SUFFIX_REGEX.test(angloMatch[3])) {
    const root = angloMatch[1].toUpperCase();
    const accidental = angloMatch[2] || '';
    const suffix = angloMatch[3] || '';
    return root + accidental + suffix;
  }

  return clean;
}

function isChordToken(token) {
  if (!token) return false;
  const t = token.trim().replace(/^[\(\[\{]+|[\)\]\}]+$/g, '').replace(/^-+|-+$/g, '');
  if (!t) return false;
  if (t === '-' || t === '/' || t === '|' || t === '->') return true;
  return isValidSingleChord(t);
}

function preprocessLineChords(line) {
  if (!line) return line;
  return line.replace(/\b(DO|RE|MI|FA|SOL|LA|SI|[A-G])(#|b)?\s+(m|min|maj7?|7|9|6|11|13|sus[24]?|dim|aug)\b/gi, '$1$2$3');
}

function isChordLine(line) {
  if (!line || !line.trim()) return false;
  const processed = preprocessLineChords(line);
  const trimmed = processed.trim();

  if (/^(=+|-+|\+|\|)/.test(trimmed)) return false;
  if (/^(CORO|INTRO|ESTROFA|VERSO|ESTRIBILLO|FINAL|PUENTE|OUTRO|SOLO)/i.test(trimmed)) return false;
  if (/[eEaAdDgGbB]\|[-0-9]/.test(trimmed)) return false;

  const tokens = trimmed.split(/[\s]+/).filter(t => t.length > 0);
  if (tokens.length === 0) return false;

  let chordCount = 0;
  for (const tok of tokens) {
    if (tok === '-' || tok === '/' || tok === '|' || tok === '->') {
      chordCount++;
      continue;
    }
    if (tok.includes('-')) {
      const subTokens = tok.split('-');
      if (subTokens.every(st => !st || isChordToken(st))) {
        chordCount++;
        continue;
      }
    }
    if (isChordToken(tok)) {
      chordCount++;
    }
  }

  return (chordCount / tokens.length) >= 0.65;
}

function extractChordsWithPositions(line) {
  const processed = preprocessLineChords(line);
  const chords = [];
  const regex = /\S+/g;
  let match;
  while ((match = regex.exec(processed)) !== null) {
    const raw = match[0];
    const index = match.index;

    if (raw.includes('-') && !raw.startsWith('-')) {
      let currentOffset = index;
      const parts = raw.split('-');
      parts.forEach(p => {
        if (p && isChordToken(p)) {
          chords.push({ chord: normalizeChord(p), index: currentOffset });
        }
        currentOffset += p.length + 1;
      });
    } else if (raw !== '-' && raw !== '/' && raw !== '|') {
      if (isChordToken(raw)) {
        chords.push({ chord: normalizeChord(raw), index });
      }
    }
  }
  return chords;
}

function mergeChordsIntoLyrics(chords, lyrics) {
  if (!lyrics || !lyrics.trim()) {
    return chords.map(c => `[${c.chord}]`).join(' ');
  }

  const sorted = [...chords].sort((a, b) => b.index - a.index);
  let result = lyrics;

  for (const { chord, index } of sorted) {
    if (index >= result.length) {
      result = result + ' ' + `[${chord}]`;
    } else {
      result = result.slice(0, index) + `[${chord}]` + result.slice(index);
    }
  }

  return result.replace(/\s+\[/g, ' [').trimEnd();
}

function isSectionHeader(line) {
  const trimmed = line.trim();
  const match = trimmed.match(/^(?:\[|\()?(CORO|ESTROFA(?:\s*\d+)?|VERSO(?:\s*\d+)?|INTRO|FINAL|PUENTE|OUTRO|SOLO)(?:\:|\)|\])?$/i);
  return match ? match[1] : null;
}

function isGenericOrUnknownArtist(artistStr) {
  if (!artistStr) return true;
  const clean = artistStr.trim().toLowerCase();
  return (
    clean === 'desconocido' ||
    clean === 'desconocida' ||
    clean === 'anonimo' ||
    clean === 'anónimo' ||
    clean === '-?-' ||
    clean === '?' ||
    clean.includes('musica catolica') ||
    clean.includes('música católica') ||
    clean.includes('mus catolica') ||
    clean.includes('musica religiosa') ||
    clean.includes('varios autores') ||
    clean.includes('tradicional') ||
    clean.includes('popular')
  );
}

function isInvalidOrTranscriber(name, trans) {
  if (!name) return true;
  const clean = name.trim().toLowerCase();
  if (isGenericOrUnknownArtist(clean)) return true;
  if (clean.includes('transcrip') || clean.includes('colaborad') || clean.includes('parroquia') || clean.includes('iglesia')) return true;
  if (clean.includes('@') || (/^[a-z0-9_\-\.]+$/i.test(clean) && !clean.includes(' '))) return true;
  if (trans) {
    const cleanTrans = trans.trim().toLowerCase();
    if (clean === cleanTrans || clean.includes(cleanTrans) || cleanTrans.includes(clean)) return true;
  }
  return false;
}

function convertRawToChordPro(text) {
  const lines = (text || '').split(/\r?\n/);
  
  let authorFromHeader = null;
  let transFromHeader = null;
  let titleFromHeader = null;
  let inHeader = false;
  let bodyStartIndex = 0;

  for (let i = 0; i < Math.min(lines.length, 35); i++) {
    const l = lines[i].trim();
    if (l.startsWith('=======')) {
      if (!inHeader) {
        inHeader = true;
      } else {
        bodyStartIndex = i + 1;
        break;
      }
    } else if (inHeader) {
      if (l.includes('AUTOR:')) {
        const parts = l.split('AUTOR:')[1].replace(/[\|\+]/g, '').trim();
        if (parts && parts !== '-?-' && parts !== '?') authorFromHeader = parts;
      }
      if (l.includes('TRANS:')) {
        const parts = l.split('TRANS:')[1].replace(/[\|\+]/g, '').trim();
        if (parts) transFromHeader = parts;
      }
      if (l.includes('CANCION:')) {
        const parts = l.split('CANCION:')[1].replace(/[\|\+]/g, '').trim();
        if (parts) titleFromHeader = parts;
      }
    }
  }

  let bodyLines = lines.slice(bodyStartIndex);
  const footerIndex = bodyLines.findIndex(l => (l.includes('lacuerda.net') || l.includes('recursoscatolicos')) && l.includes('==='));
  if (footerIndex !== -1) {
    bodyLines = bodyLines.slice(0, footerIndex);
  }

  const resultLines = [];
  const detectedChords = [];

  for (let i = 0; i < bodyLines.length; i++) {
    const currentLine = bodyLines[i];
    const trimmed = currentLine.trim();

    if (!trimmed) {
      if (resultLines.length > 0 && resultLines[resultLines.length - 1] !== '') {
        resultLines.push('');
      }
      continue;
    }

    const sectionName = isSectionHeader(trimmed);
    if (sectionName) {
      const capitalized = sectionName.charAt(0).toUpperCase() + sectionName.slice(1).toLowerCase();
      resultLines.push(`{c: ${capitalized}}`);
      continue;
    }

    if (/[eEaAdDgGbB]\|[-0-9]/.test(trimmed)) {
      resultLines.push(currentLine);
      continue;
    }

    if (trimmed.startsWith('(') && trimmed.endsWith(')')) {
      resultLines.push(`{c: ${trimmed.slice(1, -1).trim()}}`);
      continue;
    }

    if (isChordLine(currentLine)) {
      const chords = extractChordsWithPositions(currentLine);
      chords.forEach(c => {
        if (!detectedChords.includes(c.chord)) detectedChords.push(c.chord);
      });

      const nextLine = (i + 1 < bodyLines.length) ? bodyLines[i + 1] : null;

      if (nextLine !== null && nextLine.trim() && !isChordLine(nextLine) && !isSectionHeader(nextLine)) {
        const merged = mergeChordsIntoLyrics(chords, nextLine);
        resultLines.push(merged);
        i++;
      } else {
        const chordOnlyLine = chords.map(c => `[${c.chord}]`).join(' ');
        resultLines.push(chordOnlyLine);
      }
    } else {
      resultLines.push(currentLine);
    }
  }

  let chordProContent = sanitizeSongContent(resultLines.join('\n').trim());

  // Si tiene letra pero no tiene directivas {c: }, colocar {c: Estrofa 1} al inicio
  if (chordProContent && !chordProContent.includes('{c:')) {
    chordProContent = sanitizeSongContent(`{c: Estrofa 1}\n` + chordProContent);
  }

  return {
    chordPro: chordProContent,
    chords: detectedChords,
    titleFromHeader,
    authorFromHeader,
    transFromHeader
  };
}

/**
 * Busca canciones en Recursos Católicos y LaCuerda
 */
async function searchExternal(query) {
  const q = (query || '').trim();
  if (!q) return [];

  const [rcResult, lcResult] = await Promise.all([
    searchRecursosCatolicos(q).catch(err => {
      console.error('[ExternalSearch] Error en RecursosCatolicos:', err.message);
      return [];
    }),
    searchLaCuerda(q).catch(err => {
      console.error('[ExternalSearch] Error en LaCuerda:', err.message);
      return [];
    })
  ]);

  // Combinar resultados: LaCuerda primero (priorizado), luego Recursos Católicos
  return [...lcResult, ...rcResult];
}

async function searchRecursosCatolicos(query) {
  const url = `https://recursoscatolicos.com.ar/cancionero/buscar_ajax.php?s=${encodeURIComponent(query)}`;
  const html = await fetchUrl(url, 6000);
  const results = [];

  const regex = /<a\s+href=[\"']\?q=(\d+)[\"'][^>]*>[\s\S]*?<span[^>]*class=[\"'][^\"']*block text-gray-800[^\"']*[\"'][^>]*>([\s\S]*?)<\/span>/gi;
  let m;
  while ((m = regex.exec(html)) !== null) {
    const rawText = m[2]
      .replace(/&amp;/g, '&')
      .replace(/&aacute;/g, 'á')
      .replace(/&eacute;/g, 'é')
      .replace(/&iacute;/g, 'í')
      .replace(/&oacute;/g, 'ó')
      .replace(/&uacute;/g, 'ú')
      .replace(/&ntilde;/g, 'ñ')
      .replace(/\s+/g, ' ')
      .trim();

    let title = rawText;
    let artist = 'Desconocido';
    if (rawText.includes(' - ')) {
      const parts = rawText.split(' - ');
      title = parts[0].trim();
      artist = parts.slice(1).join(' - ').trim();
    }

    results.push({
      source: 'recursos_catolicos',
      sourceName: 'Recursos Católicos',
      id: m[1],
      title,
      artist,
      displayTitle: `${title} - ${artist}`
    });
  }

  return results;
}

async function searchLaCuerda(query) {
  const url = `https://acordes.lacuerda.net/busca.php?exp=${encodeURIComponent(query)}`;
  const html = await fetchUrl(url, 6000);

  const fnsMatch = html.match(/var fns=\[(.*?)\];/);

  if (!fnsMatch) return [];

  const fns = fnsMatch[1]
    .split(',')
    .map(s => s.trim().replace(/^['\"]|['\"]$/g, ''))
    .filter(Boolean)
    .reverse();

  const results = [];
  const trRegex = /<tr>\s*<td>\s*<a href=\"\/([^\/]+)\/\">([^<]+)<\/a>\s*<\/td>\s*<td>\s*<ul class=b_main[^>]*>\s*<li[^>]*id='r(\d+)'[^>]*><a href=\"javascript:\">([^<]+)<\/a>/gi;
  let m;

  while ((m = trRegex.exec(html)) !== null) {
    const artistSlug = m[1];
    const artistName = m[2].trim();
    const rowId = parseInt(m[3], 10);
    const songTitle = m[4].trim();

    // Mapeo 1 a 1 de la fila con el arreglo fns
    const songSlug = (rowId >= 0 && rowId < fns.length) ? fns[rowId] : null;

    if (artistSlug && songSlug) {
      results.push({
        source: 'lacuerda',
        sourceName: 'LaCuerda.net',
        artistSlug,
        songSlug,
        title: songTitle,
        artist: artistName,
        displayTitle: `${songTitle} - ${artistName}`
      });
    }
  }

  return results;
}

/**
 * Descarga y enriquece una canción externa seleccionada
 */
async function fetchAndEnrichSong({ source, id, artistSlug, songSlug, enrichWithAi = true, title: reqTitle, artist: reqArtist }) {
  let title = reqTitle || '';
  let artist = reqArtist || 'Desconocido';
  let initialKey = 'C';
  let youtubeUrl = '';
  let rawContent = '';

  if (source === 'recursos_catolicos') {
    const url = `https://recursoscatolicos.com.ar/cancionero/?q=${id}`;
    const html = await fetchUrl(url);

    const titleMatch = html.match(/<h2[^>]*>([\s\S]*?)<\/h2>/i);
    const artistMatch = html.match(/<h3[^>]*>([\s\S]*?)<\/h3>/i);
    const keyMatch = html.match(/<strong[^>]*>([\s\S]*?)<\/strong>/i) || html.match(/data-key=[\"']([^\"']+)[\"']/i);
    const ytMatch = html.match(/embedMedia\s*\(\s*['\"]youtube['\"]\s*,\s*['\"]([^'\"]+)['\"]\s*\)/i);
    const letraMatch = html.match(/<pre id=[\"']letra[\"'][^>]*>([\s\S]*?)<\/pre>/i);

    title = titleMatch ? titleMatch[1].replace(/<[^>]+>/g, '').trim() : (reqTitle || 'Canción');
    const rawArtist = artistMatch ? artistMatch[1].replace(/<[^>]+>/g, '').trim() : '';
    if (rawArtist && !isGenericOrUnknownArtist(rawArtist)) {
      artist = rawArtist;
    } else if (reqArtist && !isGenericOrUnknownArtist(reqArtist)) {
      artist = reqArtist;
    } else {
      artist = 'Desconocido';
    }

    const rawKey = keyMatch ? keyMatch[1].replace(/<[^>]+>/g, '').trim() : 'DO';
    initialKey = normalizeChord(rawKey) || 'C';

    if (ytMatch && ytMatch[1]) {
      youtubeUrl = ytMatch[1].replace('/embed/', '/watch?v=');
    }

    rawContent = letraMatch ? letraMatch[1].trim() : '';
  } else if (source === 'lacuerda') {
    const txtUrl = `https://acordes.lacuerda.net/TXT/${artistSlug}/${songSlug}.txt`;
    const songUrl = `https://acordes.lacuerda.net/${artistSlug}/${songSlug}`;

    const [txt, html] = await Promise.all([
      fetchUrl(txtUrl).catch(() => ''),
      fetchUrl(songUrl).catch(() => '')
    ]);

    rawContent = txt;

    // Si el .txt vino vacío o con error 500, extraer directamente del tag <pre> del HTML de la canción
    if (!rawContent || rawContent.length < 50) {
      const preMatch = html.match(/<pre[^>]*>([\s\S]*?)<\/pre>/i);
      if (preMatch && preMatch[1]) {
        rawContent = preMatch[1]
          .replace(/<A\s+href=[^>]*>([\s\S]*?)<\/A>/gi, '$1')
          .replace(/<\/?a[^>]*>/gi, '')
          .replace(/&amp;/g, '&')
          .replace(/&lt;/g, '<')
          .replace(/&gt;/g, '>')
          .replace(/&aacute;/g, 'á')
          .replace(/&eacute;/g, 'é')
          .replace(/&iacute;/g, 'í')
          .replace(/&oacute;/g, 'ó')
          .replace(/&uacute;/g, 'ú')
          .replace(/&ntilde;/g, 'ñ');
      }
    }

    // Extraer YouTube si existe en HTML
    const ytMatch = html.match(/ytVid\s*=\s*[\"']([^\"']+)[\"']/);
    if (ytMatch && ytMatch[1]) {
      let vid = ytMatch[1].trim();
      if (vid.startsWith('//')) vid = 'https:' + vid;
      youtubeUrl = vid.replace('/embed/', '/watch?v=');
    }

    // Determinar autor base desde reqArtist o artistSlug
    if (reqArtist && !isGenericOrUnknownArtist(reqArtist)) {
      artist = reqArtist.trim();
    } else if (artistSlug && !isGenericOrUnknownArtist(artistSlug)) {
      const cleanArtistSlug = artistSlug.replace(/_/g, ' ');
      artist = cleanArtistSlug
        .split(' ')
        .map(w => w.charAt(0).toUpperCase() + w.slice(1))
        .join(' ');
    } else {
      artist = 'Desconocido';
    }
  } else {
    throw new Error('Fuente no soportada: ' + source);
  }

  // Convertir a ChordPro estándar
  const converted = convertRawToChordPro(rawContent);

  if (converted.titleFromHeader && (!title || title === 'Canción')) {
    title = converted.titleFromHeader;
  }

  // Si el artista sigue siendo Desconocido, intentar extraer autor real del encabezado
  // (verificando que NO sea el transcriptor, correo o nombre de usuario de LaCuerda)
  if (isGenericOrUnknownArtist(artist) && converted.authorFromHeader) {
    const candidate = converted.authorFromHeader.trim();
    if (!isInvalidOrTranscriber(candidate, converted.transFromHeader)) {
      artist = candidate;
    }
  }

  if (isGenericOrUnknownArtist(artist)) {
    artist = 'Desconocido';
  }

  if (converted.chords.length > 0 && (!initialKey || initialKey === 'C')) {
    initialKey = converted.chords[0];
  }

  let finalChordPro = converted.chordPro;
  let categories = ['Comunión'];

  // Enriquecer con Api-IA si se solicita y hay acordes/letra
  if (enrichWithAi && finalChordPro && finalChordPro.length > 30) {
    try {
      const aiResponse = await callApiIaEnrich({
        title,
        key: initialKey,
        content: finalChordPro,
        author: artist
      });

      const enrichData = (aiResponse && aiResponse.data) ? aiResponse.data : aiResponse;

      if (enrichData) {
        if (enrichData.content) finalChordPro = enrichData.content;
        if (enrichData.key) initialKey = enrichData.key;
        if (Array.isArray(enrichData.categories) && enrichData.categories.length > 0) {
          categories = enrichData.categories;
        }
        if (artist === 'Desconocido' && enrichData.author && !isGenericOrUnknownArtist(enrichData.author)) {
          artist = enrichData.author;
        }
      }
    } catch (aiErr) {
      console.warn('[ExternalImport] Api-IA warning, usando versión parseada directa:', aiErr.message);
    }
  }

  return {
    title,
    artist,
    key: initialKey,
    youtubeUrl,
    categories,
    chordPro: finalChordPro,
    chords: converted.chords,
    source
  };
}

/**
 * Llama al endpoint de enriquecimiento de Api-IA en localhost:3001
 */
function callApiIaEnrich(data) {
  return new Promise((resolve, reject) => {
    const payload = JSON.stringify(data);
    const req = http.request(
      'http://localhost:3001/api/songs/enrich',
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      },
      (res) => {
        let resData = '';
        res.on('data', chunk => resData += chunk);
        res.on('end', () => {
          if (res.statusCode >= 200 && res.statusCode < 300) {
            try {
              resolve(JSON.parse(resData));
            } catch (e) {
              reject(e);
            }
          } else {
            reject(new Error(`Api-IA returned status ${res.statusCode}: ${resData}`));
          }
        });
      }
    );
    req.on('error', reject);
    req.setTimeout(25000, () => {
      req.destroy();
      reject(new Error('Timeout calling Api-IA'));
    });
    req.write(payload);
    req.end();
  });
}

module.exports = {
  searchExternal,
  fetchAndEnrichSong,
  convertRawToChordPro,
  normalizeChord
};

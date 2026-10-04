/**
 * Scraper para canciones de LaCuerda.net (Subcategoría Música Católica)
 * 
 * Uso:
 *   node scripts/scrape_lacuerda.js --limit 5            # Prueba con 5 canciones (guarda en JSON)
 *   node scripts/scrape_lacuerda.js --limit 5 --save-db  # Prueba e inserta directo en la Base de Datos
 *   node scripts/scrape_lacuerda.js --all               # Scrapea todas (~956 canciones) y guarda en JSON
 *   node scripts/scrape_lacuerda.js --all --save-db     # Scrapea e inserta todas en la Base de Datos
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const axios = require('axios');
const { sanitizeSongContent, normalizeSongTitle } = require('../utils/songSanitizer');

// Mapeo de notas latinas a anglosajonas (requerido por el transposer y selector de tonos de Cancionero)
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

function fetchUrl(url) {
  return new Promise((resolve, reject) => {
    https.get(url, { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)' } }, res => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return fetchUrl(res.headers.location).then(resolve).catch(reject);
      }
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve(data));
    }).on('error', reject);
  });
}

function isValidSingleChord(token) {
  if (!token) return false;
  // Manejo de acordes con bajo (slash chords, ej: D/F# o RE/FA#)
  if (token.includes('/')) {
    const parts = token.split('/');
    if (parts.length !== 2) return false;
    return isValidSingleChord(parts[0]) && isValidSingleChord(parts[1]);
  }

  const latinMatch = token.match(LATIN_ROOTS_REGEX);
  if (latinMatch && CHORD_SUFFIX_REGEX.test(latinMatch[3])) {
    return true;
  }

  const angloMatch = token.match(ANGLO_ROOTS_REGEX);
  if (angloMatch && CHORD_SUFFIX_REGEX.test(angloMatch[3])) {
    return true;
  }

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
  // Unifica acordes separados como "SI 7" -> "SI7", "MIm / SOL" -> "MIm/SOL", "Sol m" -> "Solm"
  return line.replace(/\b(DO|RE|MI|FA|SOL|LA|SI|[A-G])(#|b)?\s+(m|min|maj7?|7|9|6|11|13|sus[24]?|dim|aug)\b/gi, '$1$2$3');
}

function isChordLine(line) {
  if (!line || !line.trim()) return false;
  const processed = preprocessLineChords(line);
  const trimmed = processed.trim();

  // Si es borde de tabla, encabezado o tablatura de guitarra
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

function convertTxtToChordPro(txt) {
  const lines = txt.split(/\r?\n/);
  
  let authorFromHeader = null;
  let transFromHeader = null;
  let titleFromHeader = null;
  let inHeader = false;
  let bodyStartIndex = 0;

  for (let i = 0; i < Math.min(lines.length, 30); i++) {
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
  const footerIndex = bodyLines.findIndex(l => l.includes('lacuerda.net') && l.includes('==='));
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
      chords.forEach(c => detectedChords.push(c.chord));

      let nextLineIndex = i + 1;
      while (nextLineIndex < bodyLines.length && !bodyLines[nextLineIndex].trim()) {
        nextLineIndex++;
      }

      if (nextLineIndex < bodyLines.length) {
        const nextLine = bodyLines[nextLineIndex];
        if (!isChordLine(nextLine) && !isSectionHeader(nextLine) && !/[eEaAdDgGbB]\|[-0-9]/.test(nextLine)) {
          const merged = mergeChordsIntoLyrics(chords, nextLine);
          resultLines.push(merged);
          i = nextLineIndex;
          continue;
        }
      }

      resultLines.push(chords.map(c => `[${c.chord}]`).join(' '));
    } else {
      resultLines.push(currentLine);
    }
  }

  let detectedKey = 'C';
  if (detectedChords.length > 0) {
    const firstChord = detectedChords[0];
    const km = firstChord.match(/^([A-G][#b]?)(m)?/);
    if (km) {
      detectedKey = km[1] + (km[2] || '');
    }
  }

  while (resultLines.length > 0 && resultLines[0] === '') resultLines.shift();
  while (resultLines.length > 0 && resultLines[resultLines.length - 1] === '') resultLines.pop();

  return {
    content: resultLines.join('\n'),
    key: detectedKey,
    authorFromHeader,
    transFromHeader,
    titleFromHeader
  };
}

function isInvalidOrTranscriber(name, trans) {
  if (!name) return true;
  const clean = name.trim().toLowerCase();
  if (clean === '-?-' || clean === '?' || clean === 'desconocido' || clean === 'desconocida' || clean === 'anonimo' || clean === 'anónimo') return true;
  if (clean.includes('musica catolica') || clean.includes('música católica') || clean.includes('mus catolica') || clean.includes('musica religiosa')) return true;
  if (clean.includes('varios autores') || clean.includes('tradicional') || clean.includes('popular')) return true;
  if (clean.includes('transcrip') || clean.includes('colaborad') || clean.includes('parroquia') || clean.includes('iglesia')) return true;
  if (clean.includes('@') || (/^[a-z0-9_\-\.]+$/i.test(clean) && !clean.includes(' '))) return true;
  if (trans) {
    const cleanTrans = trans.trim().toLowerCase();
    if (clean === cleanTrans || clean.includes(cleanTrans) || cleanTrans.includes(clean)) return true;
  }
  return false;
}

async function scrapeSong(slug, fallbackTitle = '') {
  const songUrl = `https://acordes.lacuerda.net/mus_catolica/${slug}`;
  const txtUrl = `https://acordes.lacuerda.net/TXT/mus_catolica/${slug}.txt`;

  const [html, txt] = await Promise.all([
    fetchUrl(songUrl).catch(() => ''),
    fetchUrl(txtUrl).catch(() => '')
  ]);

  if (!txt || txt.length < 50) {
    return null;
  }

  // 1. Extraer Video de YouTube (script ytVid)
  let url_song = null;
  const ytMatch = html.match(/ytVid\s*=\s*["'](?:\/\/www\.youtube\.com\/embed\/)?([a-zA-Z0-9_-]{11})["']/i);
  if (ytMatch && ytMatch[1]) {
    url_song = `https://www.youtube.com/watch?v=${ytMatch[1]}`;
  }

  // 2. Extraer Título (JSON-LD -> fallback)
  let title = fallbackTitle;
  const jsonLdMatch = html.match(/<script type="application\/ld\+json">([\s\S]*?)<\/script>/i);
  if (jsonLdMatch) {
    try {
      const parsed = JSON.parse(jsonLdMatch[1]);
      if (parsed.name) title = parsed.name.trim();
    } catch (e) {}
  }

  // 3. Convertir formato de letra y acordes
  const converted = convertTxtToChordPro(txt);

  if (!title) {
    title = converted.titleFromHeader || slug.replace(/_/g, ' ');
  }

  // Si el autor viene como desconocido, -?-, anónimo, música católica, transcriptor o colaborador, asignar 'Desconocido'
  let author = converted.authorFromHeader;
  if (!author || isInvalidOrTranscriber(author, converted.transFromHeader)) {
    author = 'Desconocido';
  }

  return {
    slug,
    title,
    author,
    key: converted.key,
    url_song,
    content: converted.content
  };
}

async function getAllSongSlugs() {
  const categoryUrl = 'https://acordes.lacuerda.net/mus_catolica/';
  const html = await fetchUrl(categoryUrl);
  const matches = [...html.matchAll(/<li[^>]*><a href="([^"]+)">([^<]+)/g)];
  return matches.map(m => ({
    slug: m[1].replace(/^\//, ''),
    title: m[2].replace(/\s*<em>.*<\/em>/i, '').trim()
  }));
}

const sleep = (ms) => new Promise(r => setTimeout(r, ms));

const DEFAULT_LITURGICAL_CATEGORIES = [
  "Entrada",
  "Piedad / Perdón",
  "Gloria",
  "Aleluya / Aclamación",
  "Ofertorio",
  "Santo",
  "Paz / Cordero",
  "Comunión",
  "Meditación",
  "Salida",
  "Adoración",
  "Alabanza",
  "Mariano",
  "Navidad",
  "Cuaresma",
  "Pascua"
];

async function enrichSongWithAI(song, availableCategories) {
  try {
    const aiBase = process.env.IA_API_URL || 'http://localhost:3001/api';
    const aiUrl = `${aiBase}/songs/enrich`;

    const response = await axios.post(aiUrl, {
      title: song.title,
      key: song.key,
      content: song.content,
      categories: availableCategories
    }, { timeout: 45000 });

    if (response.data && response.data.success && response.data.data) {
      return response.data.data;
    }
  } catch (err) {
    console.log(`⚠️ IA no disponible o falló: ${err.message}`);
  }
  return null;
}

async function getOrCreateCategory(prisma, name) {
  const cleanName = (name || '').trim();
  let cat = await prisma.category.findFirst({
    where: { name: { equals: cleanName, mode: 'insensitive' } }
  });
  if (!cat) {
    cat = await prisma.category.create({
      data: { name: cleanName }
    });
  }
  return cat;
}

async function getOrCreateAuthor(prisma, name) {
  const cleanName = (name || 'Desconocido').trim();
  let author = await prisma.author.findFirst({
    where: { name: { equals: cleanName, mode: 'insensitive' } }
  });
  if (!author) {
    author = await prisma.author.create({
      data: { name: cleanName }
    });
  }
  return author;
}

async function saveSongToDb(prisma, songData) {
  // Asegurar autor
  const author = await getOrCreateAuthor(prisma, songData.author);

  // Asegurar categorías
  const categoryConnects = [];
  const cats = (songData.categories && songData.categories.length > 0) ? songData.categories : ['Música Católica'];
  for (const catName of cats) {
    const cat = await getOrCreateCategory(prisma, catName);
    categoryConnects.push({ id: cat.id });
  }

  // Crear o actualizar canción para no duplicar (usando externalSlug o título normalizado + autor)
  const normalizedTarget = normalizeSongTitle(songData.title);
  let existing = null;
  if (songData.slug) {
    existing = await prisma.song.findUnique({
      where: { externalSlug: songData.slug }
    });
  }

  if (!existing) {
    const candidateSongs = await prisma.song.findMany({
      where: { authorId: author.id },
      select: { id: true, title: true, url_song: true }
    });
    existing = candidateSongs.find(s => normalizeSongTitle(s.title) === normalizedTarget);
  }

  const cleanContent = sanitizeSongContent(songData.content);

  if (existing) {
    await prisma.song.update({
      where: { id: existing.id },
      data: {
        title: songData.title,
        content: cleanContent,
        key: songData.key,
        externalSlug: songData.slug || existing.externalSlug,
        url_song: songData.url_song || existing.url_song,
        authorId: author.id,
        categories: {
          set: categoryConnects
        }
      }
    });
    return { action: 'updated', id: existing.id, title: songData.title };
  } else {
    const created = await prisma.song.create({
      data: {
        title: songData.title,
        content: cleanContent,
        key: songData.key,
        externalSlug: songData.slug || null,
        url_song: songData.url_song,
        authorId: author.id,
        categories: {
          connect: categoryConnects
        }
      }
    });
    return { action: 'created', id: created.id, title: songData.title };
  }
}

async function main() {
  const args = process.argv.slice(2);
  const isAll = args.includes('--all');
  const saveDb = args.includes('--save-db');
  const useAi = args.includes('--ai');
  
  let limit = 10;
  const limitIdx = args.indexOf('--limit');
  if (limitIdx !== -1 && args[limitIdx + 1]) {
    limit = parseInt(args[limitIdx + 1], 10);
  }

  let offset = 0;
  const offsetIdx = args.indexOf('--offset');
  if (offsetIdx !== -1 && args[offsetIdx + 1]) {
    offset = parseInt(args[offsetIdx + 1], 10);
  }

  const force = args.includes('--force');
  const fromJson = args.includes('--from-json');
  const jsonFileIdx = args.indexOf('--json-file');
  let customJsonPath = null;
  if (jsonFileIdx !== -1 && args[jsonFileIdx + 1]) {
    customJsonPath = path.resolve(process.cwd(), args[jsonFileIdx + 1]);
  }

  // Cargar catálogo acumulativo existente
  const outputDir = path.join(__dirname, '../data');
  if (!fs.existsSync(outputDir)) fs.mkdirSync(outputDir, { recursive: true });

  const catalogFile = path.join(outputDir, 'lacuerda_mus_catolica_catalog.json');
  let cumulative = [];
  if (fs.existsSync(catalogFile)) {
    try {
      cumulative = JSON.parse(fs.readFileSync(catalogFile, 'utf-8'));
    } catch (e) {}
  }

  // MODO 1: Importación directa desde archivo JSON a la Base de Datos (sin re-scrapear ni llamar a la IA)
  if (fromJson) {
    console.log('=== SINCRONIZACIÓN DIRECTA DESDE JSON A BASE DE DATOS ===');
    const targetFile = customJsonPath || catalogFile;
    if (!fs.existsSync(targetFile)) {
      console.error(`❌ Archivo JSON no encontrado: ${targetFile}`);
      return;
    }
    const songsToImport = JSON.parse(fs.readFileSync(targetFile, 'utf-8'));
    console.log(`📁 Leyendo ${songsToImport.length} canciones desde ${targetFile}...\n`);

    const prismaClient = require('../prismaClient');
    let imported = 0;
    let updated = 0;

    for (let i = 0; i < songsToImport.length; i++) {
      const s = songsToImport[i];
      process.stdout.write(`[${i + 1}/${songsToImport.length}] Sincronizando "${s.title}"... `);
      try {
        const res = await saveSongToDb(prismaClient, s);
        if (res.action === 'created') {
          imported++;
          console.log(`✅ Creada (ID: ${res.id})`);
        } else {
          updated++;
          console.log(`🔄 Actualizada (ID: ${res.id})`);
        }
      } catch (err) {
        console.log(`❌ Error: ${err.message}`);
      }
    }

    try {
      const cache = require('../services/cache.service');
      await cache.delPattern('songs:*');
      await cache.delPattern('authors:*');
      await cache.del('stats');
    } catch (e) {}

    await prismaClient.$disconnect();
    console.log(`\n🎉 Sincronización completada: ${imported} creadas, ${updated} actualizadas.`);
    return;
  }

  console.log('=== SCRAPER LACUERDA.NET (Música Católica) ===');
  console.log(`Modo: ${isAll ? 'TODAS las canciones' : `Lote de ${limit} canciones`}`);
  console.log(`Mejora con IA: ${useAi ? 'ACTIVADA (completar acordes, secciones y categorías)' : 'DESACTIVADA'}`);
  console.log(`Guardar en Base de Datos: ${saveDb ? 'SÍ' : 'NO (Solo JSON local)'}`);
  console.log(`Forzar reprocesar existentes (--force): ${force ? 'SÍ' : 'NO'}\n`);

  console.log('1. Obteniendo listado de canciones desde https://acordes.lacuerda.net/mus_catolica/...');
  const allSongs = await getAllSongSlugs();
  console.log(`Total de canciones encontradas en LaCuerda: ${allSongs.length}`);

  const existingSlugs = new Set(cumulative.map(s => s.slug));
  console.log(`Canciones ya procesadas en catálogo: ${existingSlugs.size}`);

  // Filtrar canciones pendientes si no es --force
  const pendingSongs = force 
    ? allSongs 
    : allSongs.filter(s => !existingSlugs.has(s.slug));

  console.log(`Canciones pendientes por procesar: ${pendingSongs.length}`);

  if (pendingSongs.length === 0) {
    console.log(`\n🎉 ¡Todas las ${allSongs.length} canciones ya han sido procesadas! Usa --force si deseas reprocesarlas.`);
    return;
  }

  const targetSongs = isAll 
    ? pendingSongs.slice(offset) 
    : pendingSongs.slice(offset, offset + limit);

  console.log(`Procesando ${targetSongs.length} canciones pendientes en este lote...\n`);

  const results = [];
  let prisma = null;
  let categoryMusicaCatolica = null;
  let categoriesList = DEFAULT_LITURGICAL_CATEGORIES;

  if (saveDb) {
    prisma = require('../prismaClient');
    // Asegurar categoría base
    categoryMusicaCatolica = await getOrCreateCategory(prisma, 'Música Católica');

    try {
      const dbCategories = await prisma.category.findMany({ select: { name: true } });
      if (dbCategories.length > 0) {
        categoriesList = dbCategories.map(c => c.name);
      }
    } catch (e) {}
  }

  for (let i = 0; i < targetSongs.length; i++) {
    const globalIndex = offset + i + 1;
    const { slug, title: listTitle } = targetSongs[i];
    process.stdout.write(`[${globalIndex}/${allSongs.length}] Scrapeando: ${slug}... `);

    try {
      const songData = await scrapeSong(slug, listTitle);
      if (!songData) {
        console.log('⚠️ Sin contenido TXT válido.');
        continue;
      }

      // Si la mejora con IA está habilitada
      if (useAi) {
        process.stdout.write(`🤖 IA... `);
        const enriched = await enrichSongWithAI(songData, categoriesList);
        if (enriched) {
          songData.content = enriched.content;
          songData.key = enriched.key || songData.key;
          songData.categories = enriched.categories || ['Música Católica'];
        } else {
          songData.categories = ['Música Católica'];
        }
      } else {
        songData.categories = ['Música Católica'];
      }

      results.push(songData);
      console.log(`✅ "${songData.title}" | Tono: ${songData.key} | Cat: [${songData.categories.join(', ')}] | YT: ${songData.url_song ? 'Sí' : 'No'}`);

      // Actualizar catálogo general inmediatamente para no perder progreso
      const existingIdx = cumulative.findIndex(s => s.slug === songData.slug);
      if (existingIdx !== -1) cumulative[existingIdx] = songData;
      else cumulative.push(songData);
      fs.writeFileSync(catalogFile, JSON.stringify(cumulative, null, 2), 'utf-8');

      if (saveDb && prisma) {
        const res = await saveSongToDb(prisma, songData);
        if (res.action === 'created') {
          console.log(`   └─ Sincronizada en BD: Creada (ID: ${res.id})`);
        } else {
          console.log(`   └─ Sincronizada en BD: Actualizada (ID: ${res.id})`);
        }
      }

      // Pausa prudente para respetar rate limits de Groq/Gemini
      if (useAi) await sleep(800);
      else if (isAll) await sleep(350);

    } catch (err) {
      console.log(`❌ Error: ${err.message}`);
    }
  }

  // Guardar archivo JSON con el lote recién procesado
  const batchFile = path.join(outputDir, `lacuerda_batch_${offset}_to_${offset + results.length}.json`);
  fs.writeFileSync(batchFile, JSON.stringify(results, null, 2), 'utf-8');
  fs.writeFileSync(path.join(outputDir, 'lacuerda_batch_latest.json'), JSON.stringify(results, null, 2), 'utf-8');

  // Imprimir Auditoría del Lote
  console.log(`\n=================================================`);
  console.log(`📋 REPORTE DE AUDITORÍA DEL LOTE`);
  console.log(`=================================================`);
  console.log(`- Canciones procesadas en este lote: ${results.length}`);
  console.log(`- Total acumulado en catálogo: ${cumulative.length}/${allSongs.length}`);
  console.log(`- Canciones con Video de YouTube: ${results.filter(s => s.url_song).length}`);
  console.log(`- Canciones con directivas ChordPro ({c: }): ${results.filter(s => s.content.includes('{c:')).length}`);
  console.log(`- Categorías asignadas en el lote:`);
  const catCounts = {};
  results.forEach(s => (s.categories || []).forEach(c => catCounts[c] = (catCounts[c] || 0) + 1));
  Object.entries(catCounts).forEach(([cat, count]) => console.log(`   * ${cat}: ${count}`));

  console.log(`\nArchivos exportados:`);
  console.log(`- Lote actual: ${batchFile}`);
  console.log(`- Catálogo general: ${catalogFile}`);

  if (saveDb && prisma) {
    try {
      const cache = require('../services/cache.service');
      await cache.delPattern('songs:*');
      await cache.delPattern('authors:*');
      await cache.del('stats');
    } catch (e) {}
    await prisma.$disconnect();
    console.log(`\nCanciones sincronizadas en la base de datos y caché invalidado.`);
  }
}

if (require.main === module) {
  main().catch(err => {
    console.error('Error fatal:', err);
    process.exit(1);
  });
}

module.exports = {
  scrapeSong,
  getAllSongSlugs,
  convertTxtToChordPro,
  enrichSongWithAI
};

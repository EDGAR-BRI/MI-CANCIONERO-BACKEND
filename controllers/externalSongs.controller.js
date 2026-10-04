/**
 * externalSongs.controller.js
 * 
 * Controlador para búsqueda e importación de canciones externas
 * (Recursos Católicos y LaCuerda).
 */

const externalSongsService = require('../services/externalSongs.service');

async function searchExternal(req, res) {
  try {
    const q = req.query.q || req.query.query;
    if (!q || !q.trim()) {
      return res.status(400).json({ error: 'El parámetro de búsqueda "q" es obligatorio' });
    }

    const results = await externalSongsService.searchExternal(q.trim());
    return res.json(results);
  } catch (error) {
    console.error('[ExternalSongsController] Error en searchExternal:', error);
    return res.status(500).json({ error: 'Error al buscar canciones externas: ' + error.message });
  }
}

async function importExternalSong(req, res) {
  try {
    const { source, id, artistSlug, songSlug, enrichWithAi = true, title, artist } = req.body;

    if (!source) {
      return res.status(400).json({ error: 'El campo "source" es obligatorio (recursos_catolicos o lacuerda)' });
    }

    if (source === 'recursos_catolicos' && !id) {
      return res.status(400).json({ error: 'El campo "id" es obligatorio para canciones de Recursos Católicos' });
    }

    if (source === 'lacuerda' && (!artistSlug || !songSlug)) {
      return res.status(400).json({ error: 'Los campos "artistSlug" y "songSlug" son obligatorios para canciones de LaCuerda' });
    }

    const songData = await externalSongsService.fetchAndEnrichSong({
      source,
      id,
      artistSlug,
      songSlug,
      title,
      artist,
      enrichWithAi: enrichWithAi !== false
    });

    return res.json(songData);
  } catch (error) {
    console.error('[ExternalSongsController] Error en importExternalSong:', error);
    return res.status(500).json({ error: 'Error al importar canción externa: ' + error.message });
  }
}

module.exports = {
  searchExternal,
  importExternalSong
};

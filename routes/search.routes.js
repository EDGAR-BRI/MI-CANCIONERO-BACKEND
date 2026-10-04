const express = require('express');
const router = express.Router();
const generateController = require('../controllers/generate.controler');
const externalSongsController = require('../controllers/externalSongs.controller');
const { authenticateToken } = require('../middleware/auth.middleware');

router.post('/song', authenticateToken, generateController.searchSongByLyrics);
router.get('/external', externalSongsController.searchExternal);
router.post('/external/import', authenticateToken, externalSongsController.importExternalSong);

module.exports = router;


const express = require('express');
const router = express.Router();
const generateController = require('../controllers/generate.controler');
const { authenticateToken } = require('../middleware/auth.middleware');

router.post('/', authenticateToken, generateController.generate);
router.post('/autocomplete', authenticateToken, generateController.autocompleteChordsForLyrics);

module.exports = router;

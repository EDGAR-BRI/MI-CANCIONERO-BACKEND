const express = require('express');
const router = express.Router();
const metaController = require('../controllers/meta.controller');

router.get('/phone-prefixes', metaController.getPhonePrefixes);

module.exports = router;

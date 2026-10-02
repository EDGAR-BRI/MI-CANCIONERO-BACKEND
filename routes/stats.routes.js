const express = require('express');
const router = express.Router();
const statsController = require('../controllers/stats.controller');
const { authenticateToken, authorizeAdmin } = require('../middleware/auth.middleware');

router.get('/', statsController.getStats);
router.post('/clear-cache', authenticateToken, authorizeAdmin, statsController.clearCache);

module.exports = router;

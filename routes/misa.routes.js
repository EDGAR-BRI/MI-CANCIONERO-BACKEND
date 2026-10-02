const express = require('express');
const router = express.Router();
const misaController = require('../controllers/misa.controller');
const { authenticateToken, optionalAuth } = require('../middleware/auth.middleware');
const { pdfDownloadRateLimiter } = require('../middleware/rateLimit.middleware');

// Misa CRUD
router.get('/', optionalAuth, misaController.getAllMisas);
router.get('/:id/pdf', optionalAuth, pdfDownloadRateLimiter, misaController.exportMisaPdf);
router.get('/:id', optionalAuth, misaController.getMisaById);
router.post('/', authenticateToken, misaController.createMisa);
router.put('/:id', authenticateToken, misaController.updateMisa);
router.delete('/:id', authenticateToken, misaController.deleteMisa);

// Moments in Misa
router.post('/:id/moments', authenticateToken, misaController.addMomentToMisa);
router.delete('/:id/moments/:momentId', authenticateToken, misaController.removeMomentFromMisa);
router.put('/:id/moments/reorder', authenticateToken, misaController.reorderMoments);

// Songs in Misa
router.post('/:id/songs', authenticateToken, misaController.addSongToMisa);
router.put('/:id/songs/reorder', authenticateToken, misaController.reorderSongs);
router.put('/:id/songs/:misaSongId', authenticateToken, misaController.updateMisaSong);
router.delete('/:id/songs/:misaSongId', authenticateToken, misaController.removeSongFromMisa);

module.exports = router;

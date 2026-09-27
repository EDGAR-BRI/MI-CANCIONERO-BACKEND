const express = require('express');
const router = express.Router();
const authController = require('../controllers/auth.controller');
const { authenticateToken } = require('../middleware/auth.middleware');

router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/logout', authController.logout);
router.get('/me', authenticateToken, authController.me);
router.put('/me', authenticateToken, authController.updateProfile);

// Google OAuth
router.get('/google', authController.googleLogin);
router.post('/google/callback', authController.googleCallback);

module.exports = router;

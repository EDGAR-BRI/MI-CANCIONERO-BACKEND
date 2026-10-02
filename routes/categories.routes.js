const express = require('express');
const router = express.Router();
const categoriesController = require('../controllers/categories.controller');
const { authenticateToken, optionalAuth, authorizeAdmin } = require('../middleware/auth.middleware');

router.get('/', optionalAuth, categoriesController.getAllCategories);
router.post('/', authenticateToken, categoriesController.createCategory);
router.put('/:id', authenticateToken, authorizeAdmin, categoriesController.updateCategory);
router.delete('/:id', authenticateToken, authorizeAdmin, categoriesController.deleteCategory);

module.exports = router;

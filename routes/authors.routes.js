const express = require('express');
const router = express.Router();
const authorsController = require('../controllers/authors.controller');
const { authenticateToken, optionalAuth, authorizeAdmin } = require('../middleware/auth.middleware');

// Listar autores (público / opcional)
router.get('/', optionalAuth, authorsController.getAllAuthors);

// Obtener autor por ID
router.get('/:id', optionalAuth, authorsController.getAuthorById);

// Crear autor (usuarios autenticados)
router.post('/', authenticateToken, authorsController.createAuthor);

// Actualizar autor (usuarios autenticados o admin)
router.put('/:id', authenticateToken, authorsController.updateAuthor);

// Eliminar autor (solo admin)
router.delete('/:id', authenticateToken, authorizeAdmin, authorsController.deleteAuthor);

module.exports = router;

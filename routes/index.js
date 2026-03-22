const express = require('express');
const router = express.Router();

const songsRoutes = require('./songs.routes');
const categoriesRoutes = require('./categories.routes');


router.use('/auth', require('./auth.routes'));
router.use('/songs', songsRoutes);
router.use('/categories', categoriesRoutes);
router.use('/stats', require('./stats.routes'));
router.use('/moments', require('./moment.routes'));
router.use('/misas', require('./misa.routes'));
router.use('/users', require('./users.routes'));
router.use('/roles', require('./roles.routes'));
router.use('/check', require('./check.routes'));
router.use('/generate', require('./generate.routes'));
router.use('/search', require('./search.routes'));
router.use('/meta', require('./meta.routes'));


const permissionsRoutes = require('./permissions.routes');

// ... existing mounts ...
router.use('/permissions', permissionsRoutes);

module.exports = router;


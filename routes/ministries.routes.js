const express = require('express');
const router = express.Router();
const ministriesController = require('../controllers/ministries.controller');
const { authenticateToken } = require('../middleware/auth.middleware');

// All ministry routes require authentication
router.use(authenticateToken);

// User's ministries
router.get('/', ministriesController.getMyMinistries);
router.post('/', ministriesController.createMinistry);

// Join by code
router.post('/join', ministriesController.joinByCode);

// Ministry specific operations
router.get('/:id', ministriesController.getMinistryById);
router.put('/:id', ministriesController.updateMinistry);
router.delete('/:id', ministriesController.deleteMinistry);

// Search users & direct addition
router.get('/:id/search-users', ministriesController.searchUsers);
router.post('/:id/members/direct', ministriesController.addMemberDirectly);

// Pending requests management
router.post('/:id/requests/:userId', ministriesController.handlePendingRequest);

// Member role management & removal
router.put('/:id/members/:userId', ministriesController.updateMemberRole);
router.delete('/:id/members/:userId', ministriesController.removeMember);

// Invite code management
router.post('/:id/invite-code/regenerate', ministriesController.regenerateInviteCode);

module.exports = router;

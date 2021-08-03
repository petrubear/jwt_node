const express = require('express');
const authController = require('../controllers/auth');

// eslint-disable-next-line new-cap
const router = express.Router();

router.get('/test', authController.test);

module.exports = router;

const express = require('express');
const authController = require('../controllers/auth');
const rateLimiter = require('../helpers/rateLimiter');

// eslint-disable-next-line new-cap
const router = express.Router();

router.get('/test', rateLimiter(1, 10),
    authController.test);

module.exports = router;

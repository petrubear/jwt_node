const express = require('express');
const authController = require('../controllers/auth');
const rateLimiter = require('../helpers/rateLimiter');
// const verifyToken = require('../helpers/verifyToken');

// eslint-disable-next-line new-cap
const router = express.Router();

// router.get('/test', [rateLimiter(1, 0), verifyToken],
//     authController.test);

// [POST] token
router.post('/token', authController.token);

// [POST] register
router.post('/register', rateLimiter(1, 0),
    authController.register);


module.exports = router;

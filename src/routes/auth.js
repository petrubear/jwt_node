const express = require('express');
const authController = require('../controllers/auth');
const rateLimiter = require('../helpers/rateLimiter');
const verifyToken = require('../helpers/verifyToken');

// eslint-disable-next-line new-cap
const router = express.Router();

// router.get('/test', [rateLimiter(1, 0), verifyToken],
//     authController.test);

router.post('/login', authController.login);
// [POST] token
router.post('/token', authController.token);

// [POST] register
router.post('/register', rateLimiter(1, 0),
    authController.register);

router.post('/confirmEmailToken', verifyToken, authController.confirmEmailToken);

// [POST] Reset Password
router.post('/resetPassword', authController.resetPassword);

// [POST] Reset Password Confirm
router.post('/resetPasswordConfirm', authController.resetPasswordConfirm);

// [POST] Change Email
router.post('/changeEmail', authController.changeEmail);

// [POST] Change Email Confirm
router.post('/changeEmailConfirm', authController.changeEmailConfirm);

module.exports = router;

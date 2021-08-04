const jwt = require('jsonwebtoken');
const User = require('../model/user');
const validation = require('../helpers/validation');
const bcrypt = require('bcrypt');
const {v4: uuidv4} = require('uuid');

const register = async (req, res) => {
    try {
        const {error} = validation.registerSchema.validate(req.body, {abortEarly: false});
        if (error) {
            res.status(400).json({
                error: {
                    state: 400,
                    message: 'INPUT_ERRORS',
                    errors: error.details,
                    original: error._original,
                },
            });
        } else {
            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(req.body.password, salt);

            const user = new User({
                email: req.body.email,
                password: hashedPassword,
                emailConfirmed: false,
                emailToken: uuidv4(),
                security: {
                    tokens: [],
                    passwordReset: {
                        token: null,
                        provisionalPassword: null,
                        expiry: null,
                    },
                },
            });
            // save user
            await user.save();

            // generate access token & refresh token
            const accessToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.SECRET_ACCESS_TOKEN, {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
            });

            const refreshToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.SECRET_REFRESH_TOKEN, {
                expiresIn: process.env.REFRESH_TOKEN_EXPIRY,
            });

            // asign token to user
            await User.updateOne({email: user.email}, {
                $push: {
                    'security.tokens': {
                        refreshToken: refreshToken,
                        createdAt: new Date(),
                    },
                },
            });

            res.status(200).header().json({
                success: {
                    status: 200,
                    message: 'REGISTER_SUCCESS',
                    accessToken: accessToken,
                    refreshToken: refreshToken,
                    user: {
                        id: user.id,
                        email: user.email,
                    },
                },
            });
        }
    } catch (err) {
        let errorMessage;
        if (err.keyPattern.email === 1) {
            errorMessage = 'EMAIL_EXISTS';
        } else {
            errorMessage = err;
        }
        res.status(400).json({
            error: {
                state: 400,
                message: errorMessage,
            },
        });
    }
};

const token = async (req, res) => {
    try {
        const refreshToken = req.body.refreshToken;
        // verify if valid
        const decodeRefreshToken = jwt.verify(refreshToken, process.env.SECRET_REFRESH_TOKEN);
        const user = await User.findOne({email: decodeRefreshToken.email});
        const existingRefreshTokens = user.security.tokens;

        if (existingRefreshTokens.some((token) => token.refreshToken === refreshToken)) {
            // generate new access token
            const accessToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.SECRET_ACCESS_TOKEN, {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
            });

            // send new access token
            res.status(200).json({
                success: {
                    state: 200,
                    message: 'ACCESS_TOKEN_GENERATED',
                    accessToken: accessToken,
                },
            });
        }
        try {

        } catch (err) {
            res.status(401).json({
                error: {
                    state: 401,
                    message: 'INVALID_REFRESH_TOKEN',
                },
            });
        }
    } catch (err) {
        res.status(400).json({
            error: {
                state: 400,
                message: 'BAD_REQUEST',
            },
        });
    }
};

module.exports = {register, token};

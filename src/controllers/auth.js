const jwt = require('jsonwebtoken');
const User = require('../model/user');
const validation = require('../helpers/validation');
const bcrypt = require('bcrypt');
const {v4: uuidv4} = require('uuid');

const test = async (req, res) => {
    const user = new User({
        email: 'test@test.com',
        password: 'test',
        emailConfirmed: false,
        emailToken: 'test',
        security: {
            tokens: null,
            passwordRest: null,
        },
    });

    try {
        await user.save();
        res.send(user);
    } catch (err) {
        console.log(err);
        res.send(err);
    }
};

const token = async (req, res) => {
    const accessToken = jwt.sign({
        email: 'test@test.com',
    }, process.env.SECRET_ACCESS_TOKEN, {
        expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
    });

    res.send(accessToken);
};

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

            // generate access token
            const accessToken = jwt.sign({
                _id: user.id,
                email: user.email,
            }, process.env.SECRET_ACCESS_TOKEN, {
                expiresIn: process.env.ACCESS_TOKEN_EXPIRY,
            });

            res.status(200).header().json({
                success: {
                    status: 200,
                    message: 'REGISTER_SUCCESS',
                    accessToken: accessToken,
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

module.exports = {register};

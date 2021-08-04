const User = require('../model/user');
const jwt = require('jsonwebtoken');

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

module.exports = {test, token};

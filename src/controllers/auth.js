const User = require('../model/user');

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

module.exports = {test};

const Joi = require('joi');

const registerSchema = Joi.object({
    email: Joi.string().min(6).max(25).email(),
    password: Joi.string().min(4).max(255),
});

module.exports = {registerSchema};

const rateLimit = require('express-rate-limit');

const rateLimiter = (limit, timeframeInMinutes) => {
    return rateLimit({
        max: limit,
        windowMs: timeframeInMinutes * 60 * 1000,
        message: {
            error: {
                status: 429,
                message: 'TOO MANY REQUESTS',
                expiry: timeframeInMinutes,
            },
        },
    });
};

module.exports = rateLimiter;

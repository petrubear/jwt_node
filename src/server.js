const express = require('express');
const mongoose = require('mongoose');
const authRoutes = require('./routes/auth');

const app = express();
const port = process.env.PORT || 3000;

app.use(express.json());
app.use('/api/auth', authRoutes);

// eslint-disable-next-line max-len
const dbUri = `${process.env.DB_URI}`;
console.log(`Using mongo at ${dbUri}`);
mongoose.connect(dbUri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
    useFindAndModify: true,
    useCreateIndex: true,
}).then(() => {
    app.listen(port, () => {
        console.log(`API Listening on http://localhost:${port}`);
    });
}).catch((error) => {
    console.log(error);
});

process.on('SIGINT', () => {
    mongoose.connection.close(() => {
        console.log('mongoose disconnected on termination');
        process.exit(0);
    });
});

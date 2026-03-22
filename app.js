const express = require('express');
const cors = require('cors');
require('dotenv').config();

const routes = require('./routes');

const cookieParser = require('cookie-parser');
const morgan = require('morgan');

const app = express();

app.use(morgan('dev'));

const allowedOrigins = [
    'http://localhost:4321',
    'http://localhost:4322',
    'https://www.micancionero.online',
    ...(process.env.CORS_ORIGIN ? process.env.CORS_ORIGIN.split(',') : [])
];

const isLocalhostOrigin = (origin) => /^https?:\/\/localhost:\d+$/.test(origin);

app.use(cors({
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        if (allowedOrigins.indexOf(origin) !== -1 || isLocalhostOrigin(origin)) {
            callback(null, true);
        } else {
            console.log("Blocked by CORS:", origin);
            // Optional: return callback(new Error('Not allowed by CORS'));
            // For debugging production issues, we might want to fail loudly or log it.
            callback(null, false);
        }
    },
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

app.use('/api', routes);

app.get('/', (req, res) => {
    res.send('Lyrics App Backend is running');
});

const PORT = process.env.PORT || 3000;
if (require.main === module) {
    app.listen(PORT, () => {
        console.log(`Server running on http://localhost:${PORT}`);
    });
}

module.exports = app;

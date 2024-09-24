const mongoose = require('mongoose');
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const passport = require("passport");
const cron = require('node-cron');
const session = require("express-session");
const LocalStrategy = require("passport-local").Strategy;
const User = require("./models/userSchema")

const userRoutes = require("./routes/userRoutes");
const iqResultsRoutes = require("./routes/iqResultsRoutes");
const bcrypt = require("bcrypt");



const path = require('path');

require('dotenv').config();


const app = express();
app.use(bodyParser.json());
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());

const mongoURI = process.env.MONGODB_CONNECTION_STRING;
console.log(mongoURI);
const port = process.env.PORT || 8081;


app.use(
    session({
        secret: process.env.PASSPORT_SECRET,
        resave: false,
        saveUninitialized: false,
        cookie: {
            maxAge: 24 * 60 * 60 * 1000,
            secure: false,
            httpOnly: true,
        },
    })
);

app.use(passport.initialize());
app.use(passport.session());

mongoose.connect(mongoURI).then(() => console.log("Connected to MongoDB."))
    .catch((err) => console.log("Error connecting to MongoDB", err));

passport.use(
    new LocalStrategy(async function (username, password, done) {
        try {
            const user = await User.findOne({ username: username });
            if (!user) {
                return done(null, false, { status: 1, message: "Incorrect username." });
            }
            const match = await bcrypt.compare(password, user.password);
            if (!match) {
                return done(null, false, { status: 2, message: "Incorrect password." });
            }
            return done(null, user);
        } catch (err) {
            return done(err);
        }
    })
);

passport.serializeUser(function (user, done) {
    done(null, user.id);
});

passport.deserializeUser(async function (id, done) {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (error) {
        done(error);
    }
});

app.use('/api/v1/', userRoutes);
app.use('/api/v1/', iqResultsRoutes);

app.listen(port, '0.0.0.0', () => console.log(`Listening on port ${port}`));
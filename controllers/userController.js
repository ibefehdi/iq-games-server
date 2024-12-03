// userController.js

const User = require('../models/userSchema');
const xss = require('xss');
const bcrypt = require('bcrypt');
const passport = require("passport");
const LocalStrategy = require("passport-local").Strategy;
require('dotenv').config();
const AWS = require('aws-sdk');
const multer = require('multer');
const path = require('path');
const jwt = require('jsonwebtoken');
const ACCESS_TOKEN_SECRET = process.env.ACCESS_TOKEN_SECRET;
const REFRESH_TOKEN_SECRET = process.env.REFRESH_TOKEN_SECRET;
const s3 = new AWS.S3({
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
    endpoint: 'https://usc1.contabostorage.com',
    s3ForcePathStyle: true,
    signatureVersion: 'v4',
    region: process.env.AWS_REGION
});
const upload = multer({
    storage: multer.memoryStorage(),
    limits: {
        fileSize: 20 * 1024 * 1024, // 5MB limit
    },
    fileFilter: (req, file, cb) => {
        const allowedTypes = /jpeg|jpg|png/;
        const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
        const mimetype = allowedTypes.test(file.mimetype);

        if (extname && mimetype) {
            cb(null, true);
        } else {
            cb(new Error('Only .png, .jpg and .jpeg formats are allowed!'));
        }
    }
}).single('profileImage');
const uploadToS3 = async (file, username) => {
    const fileExtension = path.extname(file.originalname);
    const key = `profile-images/${username}${fileExtension}`;
    console.log(key)
    const params = {
        Bucket: process.env.AWS_BUCKET_NAME,
        Key: key,
        Body: file.buffer,
        ContentType: file.mimetype,
        ACL: 'public-read'
    };

    await s3.upload(params).promise();
    return `${process.env.AWS_SAVE_URL}/${key}`;
};

const generateAccessToken = (user) => {
    const payload = {
        userId: user._id,
        username: user.username,
    };

    return jwt.sign(payload, ACCESS_TOKEN_SECRET, {
        expiresIn: '1d' // Access token valid for 1 day
    });
};

const generateRefreshToken = (user) => {
    const payload = {
        userId: user._id,
    };

    return jwt.sign(payload, REFRESH_TOKEN_SECRET, {
        expiresIn: '7d' // Refresh token valid for 7 days
    });
};

function sanitizeInput(input) {
    return xss(input);
}

exports.verifyToken = async (req, res) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

    if (!token) {
        return res.status(401).json({ valid: false, message: "No token provided" });
    }

    try {
        const decoded = jwt.verify(token, ACCESS_TOKEN_SECRET);
        // Find the user without sending back the password
        const user = await User.findById(decoded.userId).select('-password');

        if (!user) {
            return res.status(404).json({ valid: false, message: "User not found" });
        }

        // Token is valid and user exists
        return res.status(200).json({
            valid: true,
            user: {
                userId: user._id,
                username: user.username,
                fName: user.fName,
                lName: user.lName,
                email: user.email,
                profileImage: user.profileImage
            }
        });
    } catch (error) {
        if (error instanceof jwt.TokenExpiredError) {
            return res.status(401).json({ valid: false, message: "Token expired" });
        }
        if (error instanceof jwt.JsonWebTokenError) {
            return res.status(401).json({ valid: false, message: "Invalid token" });
        }
        // For any other error
        console.error('Token verification error:', error);
        return res.status(500).json({ valid: false, message: "Failed to authenticate token" });
    }
};

exports.refreshToken = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;

    if (!refreshToken) {
        return res.status(401).json({ message: "Refresh token not provided" });
    }

    try {
        const decoded = jwt.verify(refreshToken, REFRESH_TOKEN_SECRET);
        const user = await User.findOne({ _id: decoded.userId, refreshToken: refreshToken });

        if (!user) {
            return res.status(403).json({ message: "Invalid refresh token" });
        }

        const accessToken = generateAccessToken(user);

        res.json({ accessToken });
    } catch (error) {
        console.error('Refresh token error:', error);
        return res.status(403).json({ message: "Invalid refresh token" });
    }
};


exports.createUser = async (req, res) => {
    try {
        // Handle file upload
        await new Promise((resolve, reject) => {
            upload(req, res, (err) => {
                if (err) reject(err);
                resolve();
            });
        });

        const sanitizedUser = {
            username: sanitizeInput(req.body.username),
            password: await bcrypt.hash(req.body.password, 10),
            fName: sanitizeInput(req.body.fName),
            lName: sanitizeInput(req.body.lName),
            email: sanitizeInput(req.body.email),
        };
        console.log(sanitizedUser);
        // Upload image if provided
        if (req.file) {
            const imageUrl = await uploadToS3(req.file, sanitizedUser.username);
            sanitizedUser.profileImage = imageUrl;
        }
        console.log(req.file);
        const user = await User.create({ ...sanitizedUser });

        res.status(201).json({
            message: "Sign-up successful.",
            username: user.username,
            fName: user.fName,
            lName: user.lName,
            _id: user._id,
            profileImage: user.profileImage
        });
    } catch (err) {
        res.status(500).json({
            message: err.message || 'Error creating user',
            error: process.env.NODE_ENV === 'development' ? err : undefined
        });
    }
};

exports.loginUser = async (req, res, next) => {
    passport.authenticate("local", async function (err, user, info) {
        if (err) {
            return next(err);
        }
        if (!user) {
            const errorCode = info.message === "Incorrect username." ? 0 : 1;
            return res.status(401).json({ code: errorCode, message: info.message });
        }

        req.logIn(user, async function (err) {
            if (err) {
                return next(err);
            }
            const accessToken = generateAccessToken(user);
            const refreshToken = generateRefreshToken(user);

            // Store refresh token in database
            user.refreshToken = refreshToken;
            await user.save();

            res.cookie('refreshToken', refreshToken, {
                httpOnly: true,
                secure: process.env.NODE_ENV === 'production',
                sameSite: 'strict',
                maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
            });

            return res.status(200).json({
                code: 4,
                message: "Authenticated successfully.",
                accessToken: accessToken,
                userId: user._id,
                profileImage:user.profileImage
            });
        });
    })(req, res, next);
};

exports.logout = async (req, res) => {
    const refreshToken = req.cookies.refreshToken;
    if (refreshToken) {
        const user = await User.findOne({ refreshToken });
        if (user) {
            user.refreshToken = null;
            await user.save();
        }
    }
    res.clearCookie('refreshToken');
    res.json({ message: "Logged out successfully" });
};

exports.getUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findById(userId).select('-password -refreshToken');

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json(user);
    } catch (err) {
        res.status(500).json({ message: "Error retrieving user", error: err.message });
    }
};

exports.updateUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const updates = {
            fName: sanitizeInput(req.body.fName),
            lName: sanitizeInput(req.body.lName),
            email: sanitizeInput(req.body.email)
        };

        // If password is being updated, hash it
        if (req.body.password) {
            updates.password = await bcrypt.hash(req.body.password, 10);
        }

        const user = await User.findByIdAndUpdate(userId, updates, { new: true, runValidators: true }).select('-password -refreshToken');

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({
            message: "User updated successfully",
            user: user
        });
    } catch (err) {
        res.status(500).json({ message: "Error updating user", error: err.message });
    }
};

exports.deleteUser = async (req, res) => {
    try {
        const userId = req.params.id;
        const user = await User.findByIdAndDelete(userId);

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ message: "User deleted successfully" });
    } catch (err) {
        res.status(500).json({ message: "Error deleting user", error: err.message });
    }
};

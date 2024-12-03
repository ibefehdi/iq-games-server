const mongoose = require('mongoose');
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    fName: { type: String, required: true },
    lName: { type: String, required: true },
    email: { type: String, default: null },
    refreshToken: { type: String, default: null },
    profileImage: { type: String, default: null }
});
module.exports = mongoose.model('User', userSchema);
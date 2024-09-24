const mongoose = require('mongoose');

const iqResultSchema = new mongoose.Schema({
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
    score: { type: Number, required: true },
    date: { type: Date, default: Date.now },
    testType: { type: String, required: true },
    details: {
        verbalScore: { type: Number },
        mathematicalScore: { type: Number },
        spatialScore: { type: Number }
    },
    percentile: { type: Number },
    notes: { type: String }
});

module.exports = mongoose.model('IQResult', iqResultSchema);
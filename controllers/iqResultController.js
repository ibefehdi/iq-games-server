const IQResult = require('../models/iqResultSchema'); // Adjust the path as needed
const User = require('../models/userSchema'); // Adjust the path as needed

// Get all IQ results for a specific user
exports.getUserIQResults = async (req, res) => {
    try {
        const userId = req.params.userId;

        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const results = await IQResult.find({ user: userId }).sort({ date: -1 });
        res.status(200).json(results);
    } catch (error) {
        res.status(500).json({ message: "Error fetching IQ results", error: error.message });
    }
};

// Get a specific IQ result by ID
exports.getIQResultById = async (req, res) => {
    try {
        const resultId = req.params.resultId;
        const result = await IQResult.findById(resultId).populate('user', 'username fName lName');

        if (!result) {
            return res.status(404).json({ message: "IQ result not found" });
        }

        res.status(200).json(result);
    } catch (error) {
        res.status(500).json({ message: "Error fetching IQ result", error: error.message });
    }
};

// Get the latest IQ result for a user
exports.getLatestUserIQResult = async (req, res) => {
    try {
        const userId = req.params.userId;

        // Check if user exists
        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        const latestResult = await IQResult.findOne({ user: userId }).sort({ date: -1 });

        if (!latestResult) {
            return res.status(404).json({ message: "No IQ results found for this user" });
        }

        res.status(200).json(latestResult);
    } catch (error) {
        res.status(500).json({ message: "Error fetching latest IQ result", error: error.message });
    }
};
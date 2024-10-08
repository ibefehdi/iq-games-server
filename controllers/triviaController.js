const axios = require('axios');
const IQResult = require('../models/iqResultSchema');

exports.getQuestions = async (req, res) => {
    try {
        const response = await axios.get('https://opentdb.com/api.php?amount=5&type=multiple&');
        const questions = response.data.results.map(q => ({
            question: q.question,
            options: [...q.incorrect_answers, q.correct_answer].sort(() => Math.random() - 0.5),
            correctAnswer: [...q.incorrect_answers, q.correct_answer].indexOf(q.correct_answer)
        }));
        res.json(questions);
    } catch (error) {
        console.error('Error fetching questions:', error);
        res.status(500).json({ error: 'Failed to fetch questions' });
    }
};
// exports.getQuestions = async (req, res) => {
//     try {
//         // Get the amount from the query parameters; default to 5 if not specified
//         const amount = parseInt(req.query.amount) || 5;
//         const halfAmount = Math.ceil(amount / 2);

//         // Fetch Mathematics questions
//         const mathResponse = await axios.get('https://opentdb.com/api.php?amount=8&type=multiple&category=19&difficulty=hard');

//         // Fetch Science & Nature questions
//         const scienceResponse = await axios.get('https://opentdb.com/api.php?amount=10&category=19&difficulty=hard&type=multiple');

//         // Combine and shuffle the questions
//         const allQuestions = [...mathResponse.data.results, ...scienceResponse.data.results];
//         const shuffledQuestions = allQuestions.sort(() => Math.random() - 0.5);

//         const questions = shuffledQuestions.map(q => {
//             const options = [...q.incorrect_answers, q.correct_answer]
//                 .map(answer => he.decode(answer))
//                 .sort(() => Math.random() - 0.5);

//             return {
//                 question: he.decode(q.question),
//                 options: options,
//                 correctAnswer: options.indexOf(he.decode(q.correct_answer))
//             };
//         });

//         res.json(questions);
//     } catch (error) {
//         console.error('Error fetching questions:', error);
//         res.status(500).json({ error: 'Failed to fetch questions' });
//     }
// };
exports.calculateIQ = async (req, res) => {
    const { score, timeSpent, userId } = req.body;
    const baseIQ = 100;
    const iq = Math.round(baseIQ + (score * 10) - (timeSpent / 10));

    try {
        const result = new IQResult({
            user: userId,
            score: iq,
            testType: 'Trivia IQ',
            notes: `Score: ${score}, Time spent: ${timeSpent} seconds`
        });
        await result.save();
        res.json({ iq, resultId: result._id });
    } catch (error) {
        console.error('Error saving IQ result:', error);
        res.status(500).json({ error: 'Failed to save IQ result' });
    }
};
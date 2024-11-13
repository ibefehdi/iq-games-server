const axios = require('axios');
const IQResult = require('../models/iqResultSchema');


// Seed words for the game
const seedWords = [
    'apple', 'book', 'cat', 'dog', 'elephant', 'flower', 'guitar', 'house', 'ice', 'jacket',
    'kite', 'lemon', 'moon', 'nest', 'ocean', 'piano', 'queen', 'rabbit', 'sun', 'tree',
    'umbrella', 'violin', 'water', 'xylophone', 'yellow', 'zebra'
];

// Get random word and its related words
exports.getWordChallenge = async (req, res) => {
    try {
        // Get random word from seed words
        const currentWord = seedWords[Math.floor(Math.random() * seedWords.length)];

        // Fetch related words from Datamuse API
        const response = await axios.get(`https://api.datamuse.com/words?rel_trg=${currentWord}&max=10`);
        const relatedWords = response.data.map(item => item.word);

        res.json({
            word: currentWord,
            relatedWords: relatedWords
        });
    } catch (error) {
        console.error('Error getting word challenge:', error);
        res.status(500).json({ error: 'Failed to get word challenge' });
    }
};

// Verify word association and calculate score
exports.verifyWord = async (req, res) => {
    try {
        const { submittedWord, currentWord } = req.body;

        // Fetch related words to verify
        const response = await axios.get(`https://api.datamuse.com/words?rel_trg=${currentWord}&max=10`);
        const relatedWords = response.data.map(item => item.word);

        // Check if submitted word is in related words
        const isCorrect = relatedWords.includes(submittedWord.toLowerCase());

        // Get next word and its related words
        const nextWord = seedWords[Math.floor(Math.random() * seedWords.length)];
        const nextWordResponse = await axios.get(`https://api.datamuse.com/words?rel_trg=${nextWord}&max=10`);
        const nextRelatedWords = nextWordResponse.data.map(item => item.word);

        res.json({
            correct: isCorrect,
            nextWord: nextWord,
            nextRelatedWords: nextRelatedWords
        });
    } catch (error) {
        console.error('Error verifying word:', error);
        res.status(500).json({ error: 'Failed to verify word' });
    }
};

// Calculate and save word association IQ score
exports.calculateWordIQ = async (req, res) => {
    const { score, timeSpent, userId } = req.body;

    // Custom IQ calculation for word association game
    // Base IQ of 100, add points for correct associations, subtract for time spent
    // Adjust multipliers based on desired difficulty
    const baseIQ = 100;
    const scoreMultiplier = 2; // Each correct answer adds 2 points
    const timeMultiplier = 0.5; // Each second subtracts 0.5 points

    const iq = Math.round(baseIQ + (score * scoreMultiplier) - (timeSpent * timeMultiplier));

    try {
        const result = new IQResult({
            user: userId,
            score: iq,
            testType: 'Word Association IQ',
            notes: `Correct Associations: ${score}, Time spent: ${timeSpent} seconds`
        });

        await result.save();

        res.json({
            iq,
            resultId: result._id
        });
    } catch (error) {
        console.error('Error saving Word Association IQ result:', error);
        res.status(500).json({ error: 'Failed to save IQ result' });
    }
};
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



const generatePattern = () => {
    const types = ['number', 'shape'];
    const type = types[Math.floor(Math.random() * types.length)];

    if (type === 'number') {
        const start = Math.floor(Math.random() * 10);
        const step = Math.floor(Math.random() * 5) + 1;
        return {
            type: 'number',
            sequence: [start, start + step, start + 2 * step, start + 3 * step],
            options: [
                start + 4 * step,
                start + 4 * step + 1,
                start + 4 * step - 1,
                start + 3 * step + 2
            ],
            correctAnswer: start + 4 * step
        };
    } else {
        const shapes = ['circle', 'square', 'triangle', 'star'];
        const sequence = [];
        for (let i = 0; i < 4; i++) {
            sequence.push(shapes[Math.floor(Math.random() * shapes.length)]);
        }
        const correctAnswer = shapes[Math.floor(Math.random() * shapes.length)];
        const options = [...new Set([...shapes, correctAnswer])].slice(0, 4);
        return { type: 'shape', sequence, options, correctAnswer };
    }
};

// Get patterns for the game
exports.getPatterns = async (req, res) => {
    try {
        const patterns = [];
        for (let i = 0; i < 10; i++) {
            patterns.push(generatePattern());
        }
        res.json(patterns);
    } catch (error) {
        console.error('Error generating patterns:', error);
        res.status(500).json({ error: 'Failed to generate patterns' });
    }
};

// Calculate and save IQ score
exports.calculatePatternIQ = async (req, res) => {
    const { score, timeSpent, userId } = req.body;

    try {
        // IQ calculation logic
        const baseIQ = 100;
        const scoreFactor = (score / 10) * 30; // 10 is total patterns
        const timeFactor = Math.max(0, 20 - (timeSpent / 10));
        const iq = Math.round(baseIQ + scoreFactor + timeFactor);

        // Save result
        const result = new IQResult({
            user: userId,
            score: iq,
            testType: 'Pattern Recognition IQ',
            notes: `Score: ${score}/10, Time spent: ${timeSpent} seconds`
        });

        await result.save();
        res.json({ iq, resultId: result._id });
    } catch (error) {
        console.error('Error calculating Pattern IQ:', error);
        res.status(500).json({ error: 'Failed to calculate and save IQ score' });
    }
};


// Define symbols array as a constant
const SYMBOLS = ['🐶', '🐱', '🐭', '🐹', '🐰', '🦊', '🐻', '🐼', '🐨', '🐯', '🦁', '🐮'];

// Initialize game cards
exports.initializeGame = async (req, res) => {
    try {
        const shuffledCards = [...SYMBOLS, ...SYMBOLS]
            .sort(() => Math.random() - 0.5)
            .map((symbol, index) => ({
                id: index,
                symbol,
                flipped: true,
                matched: false
            }));

        res.json({
            cards: shuffledCards,
            gameId: Date.now() // Simple game ID for reference
        });
    } catch (error) {
        console.error('Error initializing memory game:', error);
        res.status(500).json({ error: 'Failed to initialize game' });
    }
};

// Calculate and save memory game IQ score
exports.calculateMemoryIQ = async (req, res) => {
    const { timeSpent, moves, userId } = req.body;

    try {
        // IQ calculation logic
        const baseIQ = 100;
        const timeBonus = Math.max(0, 30 - timeSpent);
        const movePenalty = Math.max(0, moves - SYMBOLS.length * 2) * 0.5;
        const iq = Math.round(baseIQ + timeBonus - movePenalty);

        // Save result
        const result = new IQResult({
            user: userId,
            score: iq,
            testType: 'Memory Game IQ',
            notes: `Time spent: ${timeSpent} seconds, Moves: ${moves}, Pairs: ${SYMBOLS.length}`
        });

        await result.save();
        res.json({
            iq,
            resultId: result._id
        });
    } catch (error) {
        console.error('Error calculating Memory Game IQ:', error);
        res.status(500).json({ error: 'Failed to calculate and save IQ score' });
    }
};
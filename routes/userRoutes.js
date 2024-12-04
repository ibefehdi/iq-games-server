// userRoutes.js

const express = require('express');
const router = express.Router();

const {
    createUser,
    loginUser,
    getUser,
    updateUser,
    deleteUser,
    verifyToken,
    refreshToken,
    logout
} = require('../controllers/userController');

router.post('/users/signup', createUser);
router.post('/users/signin', loginUser);
router.get('/users/verify', verifyToken);
router.post('/users/refresh-token', refreshToken);
router.post('/users/logout', logout);
router.get('/users/:id', getUser);
router.put('/editUser/:id', updateUser);
router.delete('/users/:id', deleteUser);

module.exports = router;

//testing git
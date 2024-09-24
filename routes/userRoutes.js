const express = require('express');
const router = express.Router();

const { createUser, loginUser, getUser, updateUser, deleteUser } = require('../controllers/userController');

router.post('/users/signup', createUser);
router.post('/users/signin', loginUser)
router.get('/users/:id', getUser);
router.put('/users/:id', updateUser);
router.delete('/users/:id', deleteUser);

module.exports = router;
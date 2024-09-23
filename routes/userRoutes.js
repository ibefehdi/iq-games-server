const express = require('express');
const router = express.Router();

const { createUser, loginUser } = require('../controllers/userController');

router.post('/users/signup', createUser);
router.post('/users/signin', loginUser)

module.exports = router;
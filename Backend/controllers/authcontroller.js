// backend/controllers/authController.js
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const users = require('../models/usermodel');
const { SECRET_KEY } = require('../config');

exports.signUp = (req, res) => {
  const { email, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);

  const newUser = { email, password: hashedPassword };
  users.push(newUser);

  const token = jwt.sign({ email: newUser.email }, SECRET_KEY, { expiresIn: '1h' });
  res.status(200).send({ auth: true, token });
};

exports.signIn = (req, res) => {
  const { email, password } = req.body;
  const user = users.find(user => user.email === email);

  if (!user) return res.status(404).send('User not found.');

  const passwordIsValid = bcrypt.compareSync(password, user.password);

  if (!passwordIsValid) return res.status(401).send({ auth: false, token: null });

  const token = jwt.sign({ email: user.email }, SECRET_KEY, { expiresIn: '1h' });
  res.status(200).send({ auth: true, token });
};

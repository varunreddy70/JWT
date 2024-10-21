require('dotenv').config();
const express = require('express');
const jwt = require('jsonwebtoken');
const bodyParser = require('body-parser');
const bcrypt = require('bcryptjs');

const app = express();
app.use(bodyParser.json());

const users = [];

// Use environment variables
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY;

// User signup
app.post('/signup', (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  users.push({ username, password: hashedPassword });
  res.json({ message: 'User registered' });
});

// User login and token generation
app.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username);

  if (!user || !bcrypt.compareSync(password, user.password)) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }

  // Create a token using the secret key from the .env file
  const token = jwt.sign({ username: user.username }, SECRET_KEY, { expiresIn: '1h' });
  res.json({ token });
});

// Protected route
app.get('/protected', (req, res) => {
  const token = req.headers['authorization'];
  if (!token) {
    return res.status(401).json({ message: 'Access denied' });
  }

  try {
    const decoded = jwt.verify(token, SECRET_KEY);
    res.json({ message: 'Protected data', user: decoded });
  } catch (error) {
    res.status(401).json({ message: 'Invalid token' });
  }
});

app.listen(PORT, () => console.log(`Server running on http://localhost:${PORT}`));

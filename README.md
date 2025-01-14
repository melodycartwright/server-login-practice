# server-login-practice
const express = require('express');
const jwt = require('jsonwebtoken');

const app = express();

// Middleware to parse JSON request bodies
app.use(express.json());

// Secret key for JWT (use a secure and random key in production)
const SECRET_KEY = 'your_secret_key';

// In-memory database
const users = [];

// Register a new user
app.post('/register', (req, res) => {
    const { username, password } = req.body;

    // Check if the username already exists
    const userExists = users.find(user => user.username === username);
    if (userExists) {
        return res.status(400).json({ message: 'Username already exists' });
    }

    // Add new user to the "database"
    users.push({ username, password });

    // Generate JWT
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });

    res.status(201).json({ 
        message: 'User registered successfully!', token
        
    });
});


// Login a user
app.post('/login', (req, res) => {
    const { username, password } = req.body;

    // Check if the username and password match
    const user = users.find(user => user.username === username && user.password === password);
    if (!user) {
        return res.status(401).json({ message: 'Invalid username or password' });
    }

    // Generate JWT
    const token = jwt.sign({ username }, SECRET_KEY, { expiresIn: '1h' });
    res.status(200).json({ message: 'Login successful!', token: token });
});

// Middleware to verify JWT
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1]; // Bearer token
    if (!token) return res.status(401).json({ message: 'Access token is missing or invalid' });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: 'Invalid or expired token' });
        req.user = user; // Save user info to request
        next();
    });
};

// Get all users (protected route)
app.get('/users', authenticateToken, (req, res) => {
    res.status(200).json(users);
});

// Update a user's password
app.put('/users/:username', authenticateToken, (req, res) => {
    const { username } = req.params;
    const { newPassword } = req.body;

    const user = users.find(user => user.username === username);
    if (!user) {
        return res.status(404).json({ message: 'User not found' });
    }

    user.password = newPassword;
    res.status(200).json({ message: 'Password updated successfully!' });
});

// Delete a user
app.delete('/users/:username', authenticateToken, (req, res) => {
    const { username } = req.params;

    const userIndex = users.findIndex(user => user.username === username);
    if (userIndex === -1) {
        return res.status(404).json({ message: 'User not found' });
    }

    users.splice(userIndex, 1);
    res.status(200).json({ message: 'User deleted successfully!' });
});

// Start the server
app.listen(3000, () => {
    console.log('Server is running on http://localhost:3000');
});

const express = require('express');
const app = express();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const Joi = require('joi');

dotenv.config();
app.use(express.json());

const port = process.env.PORT || 3000;


const MongoClient = require('mongodb').MongoClient;
const uri = process.env.MONGO_URI;
const client = new MongoClient(uri, { useNewUrlParser: true, useUnifiedTopology: true });

client.connect((err) => {
    if (err) {
        console.error(err);
        process.exit(1);
    }
    console.log('Connected successfully to MongoDB server');

    const db = client.db('test');
    const usersCollection = db.collection('users');

    app.post('/register', async (req, res, next) => {
        try {
            const schema = Joi.object({
                username: Joi.string().required(),
                password: Joi.string().required(),
            });

            const { error } = schema.validate(req.body);
            if (error) {
                return res.status(400).json({ message: error.details[0].message });
            }

            const { username, password } = req.body;

            const existingUser = await usersCollection.findOne({ username });
            if (existingUser) {
                return res.status(400).json({ message: 'User already exists' });
            }

            const salt = await bcrypt.genSalt(10);
            const hashedPassword = await bcrypt.hash(password, salt);

            const newUser = { username, password: hashedPassword };
            const result = await usersCollection.insertOne(newUser);
            const user = result.ops[0];

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

            res.status(201).json({ user, token });
        } catch (error) {
            next(error);
        }
    });

    app.post('/login', async (req, res, next) => {
        try {
            const schema = Joi.object({
                username: Joi.string().required(),
                password: Joi.string().required(),
            });

            const { error } = schema.validate(req.body);
            if (error) {
                return res.status(400).json({ message: error.details[0].message });
            }

            const { username, password } = req.body;

            const user = await usersCollection.findOne({ username });
            if (!user) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            const isMatch = await bcrypt.compare(password, user.password);
            if (!isMatch) {
                return res.status(400).json({ message: 'Invalid credentials' });
            }

            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);

            res.status(200).json({ user, token });
        } catch (error) {
            next(error);
        }
    });


    app.post('/logout', (req, res) => {
        const token = req.cookies.token;

        // Check if user is authenticated
        if (!token) {
            return res.status(401).json({ message: "User not authenticated" });
        }

        // Remove JWT token from client-side cookies
        res.clearCookie('token');

        res.status(200).json({ message: "User logged out successfully" });
    });

    const verifyToken = (req, res, next) => {
        const token = req.cookies.token;
        if (!token) {
            return res.status(401).json({ message: "User not authenticated" });
        }

        try {
            const decoded = jwt.verify(token, process.env.JWT_SECRET);
            req.user = decoded;
            next();
        } catch (error) {
            return res.status(401).json({ message: "Invalid token" });
        }
    };

    // Add the verifyToken middleware to routes that require authentication
    app.get('/protected', verifyToken, (req, res) => {
        res.status(200).json({ message: "Protected route" });
    });
});

app.listen(port, () => console.log(`Server running on port ${port}`));



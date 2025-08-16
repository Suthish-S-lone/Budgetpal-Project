// BudgetPal - Final Node.js Backend
// Uses MongoDB for persistent storage, JWT for auth, and environment variables for security.

// --- IMPORTS ---
require('dotenv').config(); // Loads environment variables from .env file
const express = require('express');
const cors = require('cors');
const bodyParser = require('body-parser');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const mongoose = require('mongoose');
const path = require('path');

// --- INITIALIZATION ---
const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-default-super-secret-key-please-change-me';

// --- MIDDLEWARE ---
app.use(cors());
app.use(bodyParser.json());

// --- DATABASE CONNECTION ---
// Ensure you have a MONGO_URI in your .env file
if (!process.env.MONGO_URI) {
    console.error("FATAL ERROR: MONGO_URI is not defined in .env file.");
    process.exit(1);
}
mongoose.connect(process.env.MONGO_URI)
.then(() => {
    console.log("Successfully connected to MongoDB.");
})
.catch(err => {
    console.error("Connection error", err);
    process.exit(1);
});

// --- DATABASE SCHEMAS ---
const UserSchema = new mongoose.Schema({
    email: { type: String, required: true, unique: true, index: true },
    passwordHash: { type: String, required: true },
    streak: { type: Number, default: 0 },
    points: { type: Number, default: 0 },
    lastActiveDate: { type: Date },
    activeDates: [String]
});

const ExpenseSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    description: String,
    amount: Number,
    category: String,
    date: { type: Date, default: Date.now },
    recurring: Boolean,
    groupId: { type: mongoose.Schema.Types.ObjectId, ref: 'Group', default: null }
});

const GoalSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    name: String,
    targetAmount: Number,
    currentAmount: { type: Number, default: 0 }
});

const GroupSchema = new mongoose.Schema({
    name: String,
    members: [{ type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true }]
});

const BudgetSchema = new mongoose.Schema({
    userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    category: { type: String, required: true },
    amount: { type: Number, required: true }
});

const User = mongoose.model('User', UserSchema);
const Expense = mongoose.model('Expense', ExpenseSchema);
const Goal = mongoose.model('Goal', GoalSchema);
const Group = mongoose.model('Group', GroupSchema);
const Budget = mongoose.model('Budget', BudgetSchema);

// --- AUTHENTICATION MIDDLEWARE ---
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// --- API ROUTES ---

// AUTH ROUTES
app.post('/api/auth/signup', async (req, res) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
        
        const existingUser = await User.findOne({ email });
        if (existingUser) return res.status(400).json({ message: "User already exists." });

        const passwordHash = await bcrypt.hash(password, 10);
        const user = new User({ email, passwordHash });
        await user.save();

        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
        res.status(201).json({ token });
    } catch (error) {
        res.status(500).json({ message: "Server error during signup." });
    }
});

app.post('/api/auth/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await User.findOne({ email });
        if (!user) return res.status(400).json({ message: "Invalid credentials." });

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) return res.status(400).json({ message: "Invalid credentials." });

        const token = jwt.sign({ id: user._id, email: user.email }, JWT_SECRET, { expiresIn: '1d' });
        res.json({ token });
    } catch (error) {
        res.status(500).json({ message: "Server error during login." });
    }
});

// DATA ROUTES (PROTECTED)
app.get('/api/data', authenticateToken, async (req, res) => {
    try {
        const userId = req.user.id;
        const user = await User.findById(userId).select('-passwordHash');
        
        const userGroups = await Group.find({ members: userId });
        const groupIds = userGroups.map(g => g._id);

        const [expenses, goals, budgetsFromDb] = await Promise.all([
            Expense.find({ $or: [{ userId }, { groupId: { $in: groupIds } }] }).sort({ date: -1 }),
            Goal.find({ userId }),
            Budget.find({ userId })
        ]);

        const budgets = budgetsFromDb.reduce((acc, budget) => {
            acc[budget.category] = budget.amount;
            return acc;
        }, {});
        if (!budgets['Overall']) budgets['Overall'] = 50000;

        const data = {
            expenses,
            budgets,
            goals,
            groups: userGroups,
            categories: [ { name: 'Food', icon: '🍔' }, { name: 'Transport', icon: '🚗' }, { name: 'Entertainment', icon: '🎬' }, { name: 'Utilities', icon: '💡' }, { name: 'Shopping', icon: '🛍' }, { name: 'Other', icon: '❓' } ],
            quotes: [ "A budget is telling your money where to go...", "Don't save what is left after saving." ],
            user: {
                name: user.email,
                streak: user.streak,
                points: user.points,
                lastActiveDate: user.lastActiveDate,
                activeDates: user.activeDates,
                achievements: {}
            }
        };
        res.json(data);
    } catch (error) {
        res.status(500).json({ message: "Failed to fetch user data." });
    }
});

app.post('/api/expenses', authenticateToken, async (req, res) => {
    const newExpense = new Expense({ ...req.body, userId: req.user.id });
    await newExpense.save();
    res.status(201).json(newExpense);
});

app.delete('/api/expenses/:id', authenticateToken, async (req, res) => {
    const result = await Expense.findOneAndDelete({ _id: req.params.id, userId: req.user.id });
    if (!result) return res.status(404).json({ message: 'Expense not found or you do not have permission.' });
    res.status(204).send();
});

app.post('/api/budgets', authenticateToken, async (req, res) => {
    const { category, amount } = req.body;
    await Budget.findOneAndUpdate(
        { userId: req.user.id, category: category },
        { amount: amount },
        { upsert: true, new: true }
    );
    const budgetsFromDb = await Budget.find({ userId: req.user.id });
    const budgets = budgetsFromDb.reduce((acc, budget) => {
        acc[budget.category] = budget.amount;
        return acc;
    }, {});
    res.status(200).json(budgets);
});

app.post('/api/goals', authenticateToken, async (req, res) => {
    const newGoal = new Goal({ ...req.body, userId: req.user.id });
    await newGoal.save();
    res.status(201).json(newGoal);
});

app.post('/api/groups', authenticateToken, async (req, res) => {
    const { name, members } = req.body;
    const creatorId = req.user.id;
    
    const memberUsers = await User.find({ email: { $in: members } });
    const memberIds = memberUsers.map(u => u._id);
    
    const allMemberIds = [creatorId, ...memberIds];
    const uniqueMemberIds = [...new Set(allMemberIds.map(id => id.toString()))];

    const newGroup = new Group({ name, members: uniqueMemberIds });
    await newGroup.save();
    res.status(201).json(newGroup);
});

// --- SERVE FRONTEND ---
app.use(express.static(path.join(__dirname, 'public')));
app.get('*', (req, res) => {
  res.sendFile(path.resolve(__dirname, 'public', 'index.html'));
});

// --- START SERVER ---
app.listen(PORT, () => {
    console.log(`BudgetPal server is running on http://localhost:${PORT}`);
});

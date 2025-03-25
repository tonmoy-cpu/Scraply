const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
const dotenv = require('dotenv');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// MongoDB Connection
const mongoURI = process.env.MONGO_URI;

mongoose.connect(mongoURI)
  .then(() => console.log('MongoDB connected successfully'))
  .catch(err => {
    console.error('MongoDB connection error:', err.message);
    if (err.code === 8000) {
      console.error('Authentication failed. Possible causes:');
      console.error('- Incorrect username or password');
      console.error('- IP not whitelisted in MongoDB Atlas');
      console.error('- Database name mismatch or lack of access');
    }
  });

// JWT Secret
const JWT_SECRET = process.env.JWT_SECRET;

// User Schema
const userSchema = new mongoose.Schema({
  fullName: { type: String, required: true },
  username: { type: String, required: true, unique: true },
  email: { type: String, required: true, unique: true },
  phoneNumber: { type: String, required: true },
  password: { type: String, required: true },
}, { timestamps: true });

const User = mongoose.model('User', userSchema);

// Item Schema (for e-waste items)
const itemSchema = new mongoose.Schema({
  name: { type: String, required: true },
  category: { 
    type: String, 
    required: true, 
    enum: ['television', 'smartphone', 'refrigerator', 'others', 'laptop', 'accessories'] 
  },
  description: { type: String },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  facilityId: { type: mongoose.Schema.Types.ObjectId, ref: 'Facility' },
  status: { type: String, default: 'pending', enum: ['pending', 'accepted', 'recycled'] },
  createdAt: { type: Date, default: Date.now },
});

const Item = mongoose.model('Item', itemSchema);

// Facility Schema (for recycling centers)
const facilitySchema = new mongoose.Schema({
  name: { type: String, required: true },
  capacity: { type: Number, required: true },
  lon: { type: Number, required: true },
  lat: { type: Number, required: true },
  contact: { type: String, required: true },
  time: { type: String, required: true },
  verified: { type: Boolean, default: false },
  address: { type: String, required: true },
});

const Facility = mongoose.model('Facility', facilitySchema);

// JWT Authentication Middleware
const authMiddleware = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ message: 'No token, authorization denied' });

  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Token is not valid' });
  }
};

// Register Route
app.post('/api/v1/auth/register', async (req, res) => {
  const { fullName, username, email, phoneNumber, password } = req.body;

  try {
    let user = await User.findOne({ email });
    if (user) return res.status(400).json({ message: 'User already exists with this email' });

    user = await User.findOne({ username });
    if (user) return res.status(400).json({ message: 'Username already taken' });

    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);

    user = new User({ fullName, username, email, phoneNumber, password: hashedPassword });
    await user.save();

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(201).json({
      id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      phoneNumber: user.phoneNumber,
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Login Route
app.post('/api/v1/auth/login', async (req, res) => {
  const { email, password } = req.body;

  try {
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: 'Invalid email or password' });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: 'Invalid email or password' });

    const token = jwt.sign({ id: user._id }, JWT_SECRET, { expiresIn: '1h' });

    res.status(200).json({
      id: user._id,
      fullName: user.fullName,
      username: user.username,
      email: user.email,
      phoneNumber: user.phoneNumber,
      token,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Recycle Routes (for Television.tsx, Smartphone.tsx, etc.)
const categories = ['televisions', 'smartphones', 'refrigerators', 'others', 'laptops', 'accessories'];
const routeToCategory = (route) => route.slice(0, -1); // e.g., "televisions" -> "television"

// GET all items in a category
categories.forEach(category => {
  app.get(`/api/v1/recycle/${category}`, async (req, res) => {
    try {
      const items = await Item.find({ category: routeToCategory(category) })
        .populate('userId', 'username')
        .populate('facilityId', 'name address');
      res.status(200).json(items);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  });

  // POST a new item to a category (protected)
  app.post(`/api/v1/recycle/${category}`, authMiddleware, async (req, res) => {
    const { name, description, facilityId } = req.body;

    try {
      const item = new Item({
        name,
        category: routeToCategory(category),
        description,
        userId: req.user.id,
        facilityId: facilityId || null, // Optional facility assignment
      });

      await item.save();
      const populatedItem = await Item.findById(item._id)
        .populate('userId', 'username')
        .populate('facilityId', 'name address');
      res.status(201).json(populatedItem);
    } catch (error) {
      console.error(error);
      res.status(500).json({ message: 'Server error' });
    }
  });
});

// Facility Routes
app.get('/api/v1/facilities', async (req, res) => {
  try {
    const facilities = await Facility.find();
    res.status(200).json(facilities);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});

// Seed Facilities (Run once to populate DB with facility.ts data)
// Uncomment and run this once, then comment it out again
/*
app.post('/api/v1/facilities/seed', async (req, res) => {
  const facilityData = require('./facilityData'); // Copy facility.ts data here
  try {
    await Facility.deleteMany(); // Clear existing facilities
    const facilities = await Facility.insertMany(facilityData);
    res.status(201).json(facilities);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: 'Server error' });
  }
});
*/

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
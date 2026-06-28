require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');

const app = express();
app.use(express.json());
app.use(express.static('public'));

// 1. Database Connection
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log('MongoDB Connected!'))
  .catch(err => console.log('DB Error:', err));

// 2. Database Models
const User = mongoose.model('User', new mongoose.Schema({
  username: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}));

// Notice how comments are embedded directly into the Post schema
const PostSchema = new mongoose.Schema({
  title: { type: String, required: true },
  content: { type: String, required: true },
  author: { type: String, required: true },
  createdAt: { type: Date, default: Date.now },
  comments: [{
    text: String,
    author: String,
    createdAt: { type: Date, default: Date.now }
  }]
});
const Post = mongoose.model('Post', PostSchema);

// 3. Security Middleware
const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Log in to perform this action' });
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET || 'supersecretkey');
    next();
  } catch (err) {
    res.status(400).json({ error: 'Invalid token' });
  }
};

// 4. API Routes
// Auth: Register & Login
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);
  try {
    const user = new User({ username, password: hashedPassword });
    await user.save();
    res.json({ message: 'Registered successfully!' });
  } catch (err) {
    res.status(400).json({ error: 'Username might already exist' });
  }
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body;
  const user = await User.findOne({ username });
  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }
  const token = jwt.sign({ id: user._id, username: user.username }, process.env.JWT_SECRET || 'supersecretkey');
  res.json({ token, username: user.username });
});

// Posts: Get all (Public)
app.get('/api/posts', async (req, res) => {
  const posts = await Post.find().sort({ createdAt: -1 }); // Newest first
  res.json(posts);
});

// Posts: Create (Protected)
app.post('/api/posts', authenticate, async (req, res) => {
  const { title, content } = req.body;
  const post = new Post({ title, content, author: req.user.username });
  await post.save();
  res.json(post);
});

// Posts: Delete (Protected, Author only)
app.delete('/api/posts/:id', authenticate, async (req, res) => {
  const post = await Post.findById(req.params.id);
  if (post.author !== req.user.username) return res.status(403).json({ error: 'You can only delete your own posts' });
  await Post.findByIdAndDelete(req.params.id);
  res.json({ message: 'Post deleted' });
});

// Comments: Add to a post (Protected)
app.post('/api/posts/:id/comments', authenticate, async (req, res) => {
  const post = await Post.findById(req.params.id);
  post.comments.push({ text: req.body.text, author: req.user.username });
  await post.save();
  res.json(post);
});

// Fallback to frontend
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'public', 'index.html')));

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));

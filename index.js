// index.js — secure (no hardcoded DB URI, fails fast)
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import rateLimit from "express-rate-limit";

dotenv.config();

const app = express();
app.use(express.json());

// CORS — replace with your real frontend/game origin(s)
app.use(
  cors({
    origin: ["https://your-game-domain.com", "http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);

// Rate limiter
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: "Too many requests, please try again later.",
});
app.use(limiter);

// Fail fast if MONGODB_URI not provided
if (!process.env.MONGODB_URI) {
  console.error("❌ FATAL: MONGODB_URI is not set. Please set it in environment variables.");
  process.exit(1); // stop the app — prevents accidental run with no DB or wrong config
}

// Connect DB
mongoose
  .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Connection Error:", err);
    process.exit(1); // critical — exit so process manager / render shows failure
  });

// Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  gameId: String,
});
const User = mongoose.model("User", userSchema);

// Auth middleware
const verifyToken = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ message: "Access Denied: No token provided" });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch (err) {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
};

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameId } = req.body;
    if (!email || !password || !gameId) return res.status(400).json({ message: "All fields required" });
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already registered" });
    const hash = await bcrypt.hash(password, 12);
    const user = new User({ email, password: hash, gameId });
    await user.save();
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.status(201).json({ message: "Signup successful", token, userId: user._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });
    res.json({ message: "Login successful", token, userId: user._id });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Protected user route
app.get("/user/:id", verifyToken, async (req, res) => {
  try {
    if (req.userId !== req.params.id) return res.status(403).json({ message: "Unauthorized access" });
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

// Root
app.get("/", (req, res) => res.send("✅ Vansh Backend Secure"));

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// 🧩 Debug log to confirm env is loaded
console.log("🔍 Checking MONGODB_URI:", process.env.MONGODB_URI ? "✅ Found" : "❌ Missing");

// ✅ MongoDB connection (safe fallback)
const mongoURI =
  process.env.MONGODB_URI ||
  "mongodb+srv://Vansh:Vansh000@atlas-sql-690b384c642f83707e3b32f6-zrhyke.a.query.mongodb.net/Vansh?retryWrites=true&w=majority&appName=Cluster0";

mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => console.log("❌ MongoDB Connection Error:", err));

// 🧩 User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  gameId: String,
});

const User = mongoose.model("User", userSchema);

// 🟢 Signup route
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameId } = req.body;
    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hash, gameId });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallbackSecretKey");
    res.json({ message: "Signup successful", token, userId: user._id });
  } catch (err) {
    res.status(500).json({ message: "Error: " + err.message });
  }
});

// 🟢 Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET || "fallbackSecretKey");
    res.json({ message: "Login successful", token, userId: user._id });
  } catch (err) {
    res.status(500).json({ message: "Error: " + err.message });
  }
});

// 🟣 NEW: Load user details route
app.get("/user/:id", async (req, res) => {
  try {
    const user = await User.findById(req.params.id).select("-password"); // hide password
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ message: "User details loaded", user });
  } catch (err) {
    res.status(500).json({ message: "Error: " + err.message });
  }
});

// 🟢 Root test route
app.get("/", (req, res) => {
  res.send("✅ Vansh Backend Auth System Running");
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`🚀 Server running on port ${PORT}`));

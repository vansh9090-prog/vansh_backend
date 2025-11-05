// Simple Express backend with user signup/login system
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

// MongoDB connection
mongoose.connect(process.env.mongodb://atlas-sql-690b384c642f83707e3b32f6-zrhyke.a.query.mongodb.net/Vansh?ssl=true&authSource=admin)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.log("❌ MongoDB Error:", err));

// User Schema
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true },
  password: String,
  gameId: String
});

const User = mongoose.model("User", userSchema);

// Signup route
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameId } = req.body;

    const userExist = await User.findOne({ email });
    if (userExist) return res.status(400).json({ message: "Email already registered" });

    const hash = await bcrypt.hash(password, 10);
    const user = new User({ email, password: hash, gameId });
    await user.save();

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ message: "Signup successful", token });
  } catch (err) {
    res.status(500).json({ message: "Error: " + err.message });
  }
});

// Login route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "User not found" });

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) return res.status(400).json({ message: "Invalid password" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET);
    res.json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ message: "Error: " + err.message });
  }
});

app.get("/", (req, res) => {
  res.send("✅ Vansh Backend Auth System Running");
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log("🚀 Server running on port " + PORT));

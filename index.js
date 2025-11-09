// index.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";

const app = express();
app.use(express.json());
app.use(cors());

// ---------------- Schema ----------------
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  gameName: { type: String, required: true },  // player's name in game
  wallet: { type: Number, default: 1000 },     // default wallet balance
  gameUid: { type: String, required: true, unique: true }, // 10-digit unique ID
});

const User = mongoose.model("User", userSchema);

// ---------------- Middleware ----------------
const verifyToken = (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token provided" });

    const token = authHeader.split(" ")[1];
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.userId = decoded.id;
    next();
  } catch {
    res.status(401).json({ message: "Invalid token" });
  }
};

// ---------------- Signup ----------------
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameName } = req.body;
    if (!email || !password || !gameName)
      return res.status(400).json({ message: "Missing required fields" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashedPassword = await bcrypt.hash(password, 10);

    // Generate 10-digit unique Game UID
    let gameUid;
    let unique = false;
    while (!unique) {
      gameUid = Math.floor(1000000000 + Math.random() * 9000000000).toString();
      const uidExists = await User.findOne({ gameUid });
      if (!uidExists) unique = true;
    }

    const newUser = new User({
      email,
      password: hashedPassword,
      gameName,
      wallet: 1000,
      gameUid,
    });

    await newUser.save();

    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.status(201).json({
      message: "Signup successful",
      token,
      user: {
        email: newUser.email,
        gameName: newUser.gameName,
        wallet: newUser.wallet,
        gameUid: newUser.gameUid,
      },
    });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- Login ----------------
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ message: "Missing fields" });

    const user = await User.findOne({ email });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const validPass = await bcrypt.compare(password, user.password);
    if (!validPass)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "7d",
    });

    res.json({
      message: "Login successful",
      token,
      user: {
        email: user.email,
        gameName: user.gameName,
        wallet: user.wallet,
        gameUid: user.gameUid,
      },
    });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- Protected route (example) ----------------
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- Server Start ----------------
mongoose
  .connect(process.env.MONGO_URL)
  .then(() => {
    console.log("✅ MongoDB Connected");
    app.listen(process.env.PORT, () =>
      console.log(`🚀 Server running on port ${process.env.PORT}`)
    );
  })
  .catch((err) => console.error("MongoDB Error:", err));

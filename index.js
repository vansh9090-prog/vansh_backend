// index.js
import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import cors from "cors";
import { OAuth2Client } from "google-auth-library";

const app = express();
app.use(express.json());
app.use(cors());

// ---------------- Google Auth Client ----------------
const googleClient = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ---------------- Schema ----------------
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true },
  password: { type: String },
  gameName: { type: String },
  wallet: { type: Number, default: 1000 },
  gameUid: { type: String, unique: true },
  loginMethod: { type: String, default: "email" }, // "email" or "google"
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

// ---------------- Helper: Generate Unique Game UID ----------------
async function generateGameUid() {
  let uid;
  let unique = false;
  while (!unique) {
    uid = Math.floor(1000000000 + Math.random() * 9000000000).toString();
    const exists = await User.findOne({ gameUid: uid });
    if (!exists) unique = true;
  }
  return uid;
}

// ---------------- Signup ----------------
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameName } = req.body;
    if (!email || !password || !gameName)
      return res.status(400).json({ message: "Missing required fields" });

    const existing = await User.findOne({ email });
    if (existing) return res.status(400).json({ message: "Email already exists" });

    const hashed = await bcrypt.hash(password, 10);
    const gameUid = await generateGameUid();

    const newUser = new User({
      email,
      password: hashed,
      gameName,
      wallet: 1000,
      gameUid,
      loginMethod: "email",
    });

    await newUser.save();
    const token = jwt.sign({ id: newUser._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

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

    const valid = await bcrypt.compare(password, user.password);
    if (!valid)
      return res.status(400).json({ message: "Invalid credentials" });

    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

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

// ---------------- Google Login ----------------
app.post("/google-login", async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ message: "Missing Google token" });

    // Verify Google token
    const ticket = await googleClient.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || "Player";

    let user = await User.findOne({ email });

    // Create new user if not exists
    if (!user) {
      const gameUid = await generateGameUid();
      user = new User({
        email,
        gameName: name,
        wallet: 1000,
        gameUid,
        loginMethod: "google",
      });
      await user.save();
    }

    // Create JWT token for our server
    const jwtToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: "7d" });

    res.json({
      message: "Google login successful",
      token: jwtToken,
      user: {
        email: user.email,
        gameName: user.gameName,
        wallet: user.wallet,
        gameUid: user.gameUid,
        loginMethod: user.loginMethod,
      },
    });
  } catch (err) {
    console.error("Google login error:", err);
    res.status(500).json({ message: "Google login failed" });
  }
});

// ---------------- Profile (Protected) ----------------
app.get("/profile", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch {
    res.status(500).json({ message: "Server error" });
  }
});

// ---------------- Root ----------------
app.get("/", (req, res) => {
  res.send("✅ Vansh Backend Auth System with Google Login Running");
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

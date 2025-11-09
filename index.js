// index.js
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { OAuth2Client } from "google-auth-library";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

const {
  MONGODB_URI,
  JWT_SECRET,
  GOOGLE_CLIENT_ID,
  PORT = 10000,
  ALLOW_FALLBACK_MONGO = "false",
} = process.env;

console.log("📦 ENV loaded:", {
  MONGODB_URI: MONGODB_URI ? "✅ Found" : "❌ Missing",
  JWT_SECRET: JWT_SECRET ? "✅ Found" : "❌ Missing",
  GOOGLE_CLIENT_ID: GOOGLE_CLIENT_ID ? "✅ Found" : "❌ Missing",
  PORT,
  ALLOW_FALLBACK_MONGO,
});

if (!MONGODB_URI && ALLOW_FALLBACK_MONGO !== "true") {
  console.error("❌ FATAL: MONGODB_URI is not set. Please set it in environment variables.");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET is not set. Please set it in environment variables.");
  process.exit(1);
}

const mongoURI = MONGODB_URI || (ALLOW_FALLBACK_MONGO === "true" ? "mongodb://localhost:27017/vansh_dev_fallback" : null);
if (!mongoURI) {
  console.error("❌ No mongoURI available and fallback not allowed. Exiting.");
  process.exit(1);
}

mongoose
  .connect(mongoURI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch((err) => {
    console.error("❌ MongoDB Connection Error:", err && err.message ? err.message : err);
    process.exit(1);
  });

const googleClient = GOOGLE_CLIENT_ID ? new OAuth2Client(GOOGLE_CLIENT_ID) : null;

// User schema
const userSchema = new mongoose.Schema({
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  password: { type: String },
  gameName: { type: String, required: true },
  wallet: { type: Number, default: 1000 },
  gameUid: { type: String, required: true, unique: true },
  loginMethod: { type: String, enum: ["email", "google"], default: "email" },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

// helpers
const createToken = (userId) => jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });
async function generateUniqueGameUid() {
  while (true) {
    const uid = Math.floor(1000000000 + Math.random() * 9000000000).toString();
    const found = await User.findOne({ gameUid: uid }).select("_id").lean();
    if (!found) return uid;
  }
}

// auth middleware
const verifyToken = (req, res, next) => {
  try {
    const auth = req.headers.authorization;
    if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ message: "Token missing" });
    const token = auth.split(" ")[1];
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// routes
app.get("/", (req, res) => res.json({ ok: true, message: "Vansh Backend Running" }));

app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameName } = req.body;
    if (!email || !password || !gameName) return res.status(400).json({ message: "email, password and gameName required" });

    const exists = await User.findOne({ email: email.toLowerCase().trim() });
    if (exists) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 12);
    const gameUid = await generateUniqueGameUid();

    const user = new User({
      email: email.toLowerCase().trim(),
      password: hashed,
      gameName: String(gameName).trim(),
      wallet: 1000,
      gameUid,
      loginMethod: "email",
    });

    await user.save();
    const token = createToken(user._id);

    res.status(201).json({
      message: "Signup successful",
      token,
      user: { email: user.email, gameName: user.gameName, wallet: user.wallet, gameUid: user.gameUid },
    });
  } catch (err) {
    console.error("Signup error:", err && err.message ? err.message : err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "email and password required" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user || !user.password) return res.status(400).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });

    const token = createToken(user._id);
    res.json({ message: "Login successful", token, user: { email: user.email, gameName: user.gameName, wallet: user.wallet, gameUid: user.gameUid } });
  } catch (err) {
    console.error("Login error:", err && err.message ? err.message : err);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/google-login", async (req, res) => {
  try {
    if (!googleClient) return res.status(500).json({ message: "Google login not configured on server" });
    const { idToken } = req.body;
    if (!idToken) return res.status(400).json({ message: "Missing Google idToken" });

    const ticket = await googleClient.verifyIdToken({ idToken, audience: GOOGLE_CLIENT_ID });
    const payload = ticket.getPayload();
    const email = payload.email;
    const name = payload.name || `Player${Math.floor(Math.random() * 9999)}`;

    let user = await User.findOne({ email });
    if (!user) {
      const gameUid = await generateUniqueGameUid();
      user = new User({ email, gameName: name, wallet: 1000, gameUid, loginMethod: "google" });
      await user.save();
    }

    const token = createToken(user._id);
    res.json({ message: "Google login successful", token, user: { email: user.email, gameName: user.gameName, wallet: user.wallet, gameUid: user.gameUid } });
  } catch (err) {
    console.error("Google login error:", err && err.message ? err.message : err);
    res.status(500).json({ message: "Google login failed" });
  }
});

app.get("/me", verifyToken, async (req, res) => {
  try {
    const u = await User.findById(req.userId).select("-password");
    if (!u) return res.status(404).json({ message: "User not found" });
    res.json({ user: u });
  } catch (err) {
    console.error("/me error:", err && err.message ? err.message : err);
    res.status(500).json({ message: "Server error" });
  }
});

app.patch("/me", verifyToken, async (req, res) => {
  try {
    const { gameName } = req.body;
    if (!gameName) return res.status(400).json({ message: "gameName required" });
    const updated = await User.findByIdAndUpdate(req.userId, { gameName: String(gameName).trim() }, { new: true }).select("-password");
    res.json({ message: "Updated", user: updated });
  } catch (err) {
    console.error("/me patch error:", err && err.message ? err.message : err);
    res.status(500).json({ message: "Server error" });
  }
});

app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));

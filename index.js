// index.js — secure, no hard-coded secrets (fail-fast)
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

// --- Basic config from environment (NO hard-coded secrets here) ---
const {
  MONGODB_URI,
  JWT_SECRET,
  FRONTEND_ORIGINS, // optional, comma-separated list of allowed origins
  PORT = 10000, // optional, can be overridden in Render
} = process.env;

// Fail-fast for critical secrets
if (!MONGODB_URI) {
  console.error("❌ FATAL: MONGODB_URI is not set. Please set it in environment variables.");
  process.exit(1);
}
if (!JWT_SECRET) {
  console.error("❌ FATAL: JWT_SECRET is not set. Please set it in environment variables.");
  process.exit(1);
}

// --- CORS setup ---
// If FRONTEND_ORIGINS provided (comma separated), use whitelist; otherwise allow all.
// (Recommended: set FRONTEND_ORIGINS in Render to restrict origins)
let corsOptions;
if (FRONTEND_ORIGINS) {
  const allowed = FRONTEND_ORIGINS.split(",").map(u => u.trim()).filter(Boolean);
  corsOptions = {
    origin: (origin, callback) => {
      // allow requests with no origin (mobile apps, curl, Postman)
      if (!origin) return callback(null, true);
      if (allowed.indexOf(origin) !== -1) return callback(null, true);
      callback(new Error("CORS blocked by server"));
    },
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
  };
} else {
  // No origins set — allow all (use only for development) — recommended to set FRONTEND_ORIGINS in production
  corsOptions = {
    origin: true,
    methods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    credentials: true,
  };
}
app.use(cors(corsOptions));

// --- Rate limiter (basic protection) ---
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // limit each IP to 200 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  message: { message: "Too many requests, please try again later." },
});
app.use(limiter);

// --- Connect to MongoDB ---
mongoose
  .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => {
    console.error("❌ MongoDB connection error:", err);
    process.exit(1); // critical — exit so deployment shows failure
  });

// --- User schema/model ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  gameId: { type: String, required: true, trim: true },
  role: { type: String, default: "user" }, // future: admin/moderator
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

// --- Auth middleware (JWT) ---
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ message: "Access denied: token missing" });
  }
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    req.tokenIssuedAt = payload.iat;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// --- Helper: create token (short expiry recommended) ---
const createToken = (userId) => {
  return jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" }); // change as needed
};

// --- Routes ---
// Health
app.get("/", (req, res) => res.json({ ok: true, message: "Vansh Backend Running" }));

// Signup (public)
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameId } = req.body;
    if (!email || !password || !gameId) return res.status(400).json({ message: "All fields are required" });

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ email: email.toLowerCase().trim(), password: hashed, gameId: String(gameId).trim() });
    await user.save();

    const token = createToken(user._id);
    res.status(201).json({ message: "Signup successful", token, userId: user._id });
  } catch (err) {
    console.error("Signup error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Login (public)
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ email: email.toLowerCase().trim() });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });

    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(400).json({ message: "Invalid credentials" });

    const token = createToken(user._id);
    res.json({ message: "Login successful", token, userId: user._id });
  } catch (err) {
    console.error("Login error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Protected: get own profile
app.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    console.error("Me route error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Protected: get other user by id only if same user or admin
app.get("/user/:id", verifyToken, async (req, res) => {
  try {
    if (req.userId !== req.params.id) {
      // allow if requester is admin
      const requester = await User.findById(req.userId);
      if (!requester || requester.role !== "admin") {
        return res.status(403).json({ message: "Unauthorized access" });
      }
    }
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) {
    console.error("/user/:id error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Example protected update (only owner or admin)
app.put("/user/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.userId !== id) {
      const requester = await User.findById(req.userId);
      if (!requester || requester.role !== "admin") {
        return res.status(403).json({ message: "Unauthorized" });
      }
    }
    const updates = {};
    if (req.body.gameId) updates.gameId = String(req.body.gameId).trim();
    // do not allow email/password changes here — implement separate endpoints with validation
    const updated = await User.findByIdAndUpdate(id, updates, { new: true }).select("-password");
    res.json({ message: "Updated", user: updated });
  } catch (err) {
    console.error("Update user error:", err);
    res.status(500).json({ message: "Server error" });
  }
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));

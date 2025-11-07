// index.js — secure backend with B2 storage
import express from "express";
import mongoose from "mongoose";
import dotenv from "dotenv";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import B2 from "backblaze-b2";

dotenv.config();

const app = express();
app.use(express.json());

const {
  MONGODB_URI,
  JWT_SECRET,
  FRONTEND_ORIGINS,
  PORT = 10000,
  B2_APP_KEY_ID,
  B2_APP_KEY,
  B2_BUCKET_ID,
  B2_BUCKET_NAME,
} = process.env;

// --- Fail-fast for critical secrets ---
if (!MONGODB_URI || !JWT_SECRET || !B2_APP_KEY_ID || !B2_APP_KEY || !B2_BUCKET_ID || !B2_BUCKET_NAME) {
  console.error("❌ FATAL: Missing critical environment variables.");
  process.exit(1);
}

// --- CORS setup ---
let corsOptions;
if (FRONTEND_ORIGINS) {
  const allowed = FRONTEND_ORIGINS.split(",").map(u => u.trim()).filter(Boolean);
  corsOptions = {
    origin: (origin, callback) => {
      if (!origin) return callback(null, true);
      if (allowed.indexOf(origin) !== -1) return callback(null, true);
      callback(new Error("CORS blocked by server"));
    },
    methods: ["GET","POST","PUT","DELETE","OPTIONS"],
    credentials: true,
  };
} else {
  corsOptions = { origin: true, methods: ["GET","POST","PUT","DELETE","OPTIONS"], credentials: true };
}
app.use(cors(corsOptions));

// --- MongoDB connection ---
mongoose
  .connect(MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => { console.error("❌ MongoDB error:", err); process.exit(1); });

// --- User schema ---
const userSchema = new mongoose.Schema({
  email: { type: String, unique: true, required: true, lowercase: true, trim: true },
  password: { type: String, required: true },
  gameId: { type: String, required: true, trim: true },
  role: { type: String, default: "user" },
}, { timestamps: true });

const User = mongoose.models.User || mongoose.model("User", userSchema);

// --- JWT middleware ---
const verifyToken = (req, res, next) => {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ message: "Access denied: token missing" });
  const token = auth.split(" ")[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.id;
    next();
  } catch {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

// --- Helper: create token ---
const createToken = (userId) => jwt.sign({ id: userId }, JWT_SECRET, { expiresIn: "7d" });

// --- Backblaze B2 setup ---
const b2 = new B2({ applicationKeyId: B2_APP_KEY_ID, applicationKey: B2_APP_KEY });

const b2Authorize = async () => {
  try { await b2.authorize(); console.log("✅ Backblaze B2 authorized"); }
  catch (err) { console.error("❌ B2 auth error:", err); }
};
b2Authorize();

// --- Routes ---

// Health
app.get("/", (req, res) => res.json({ ok: true, message: "Backend Running" }));

// Signup
app.post("/signup", async (req, res) => {
  try {
    const { email, password, gameId } = req.body;
    if (!email || !password || !gameId) return res.status(400).json({ message: "All fields required" });

    const existing = await User.findOne({ email: email.toLowerCase().trim() });
    if (existing) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, 12);
    const user = new User({ email: email.toLowerCase().trim(), password: hashed, gameId: String(gameId).trim() });
    await user.save();

    const token = createToken(user._id);
    res.status(201).json({ message: "Signup successful", token, userId: user._id });
  } catch (err) { console.error("Signup error:", err); res.status(500).json({ message: "Server error" }); }
});

// Login
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
  } catch (err) { console.error("Login error:", err); res.status(500).json({ message: "Server error" }); }
});

// Get own profile
app.get("/me", verifyToken, async (req, res) => {
  try {
    const user = await User.findById(req.userId).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) { console.error("Me error:", err); res.status(500).json({ message: "Server error" }); }
});

// Upload file to B2
app.post("/upload", verifyToken, async (req, res) => {
  try {
    const { fileName, base64Data } = req.body;
    if (!fileName || !base64Data) return res.status(400).json({ message: "fileName and base64Data required" });

    const buffer = Buffer.from(base64Data, "base64");

    const uploadUrlResponse = await b2.getUploadUrl({ bucketId: B2_BUCKET_ID });
    const uploadUrl = uploadUrlResponse.data.uploadUrl;
    const uploadAuthToken = uploadUrlResponse.data.authorizationToken;

    await b2.uploadFile({ uploadUrl, uploadAuthToken, fileName, data: buffer, contentType: "image/png" });

    const fileUrl = `https://f001.backblazeb2.com/file/${B2_BUCKET_NAME}/${fileName}`;
    res.json({ message: "Upload successful", fileUrl });
  } catch (err) { console.error("B2 upload error:", err); res.status(500).json({ message: "Upload failed" }); }
});

// Get other user by ID (admin check)
app.get("/user/:id", verifyToken, async (req, res) => {
  try {
    if (req.userId !== req.params.id) {
      const requester = await User.findById(req.userId);
      if (!requester || requester.role !== "admin") return res.status(403).json({ message: "Unauthorized" });
    }
    const user = await User.findById(req.params.id).select("-password");
    if (!user) return res.status(404).json({ message: "User not found" });
    res.json({ user });
  } catch (err) { console.error("/user/:id error:", err); res.status(500).json({ message: "Server error" }); }
});

// Update user
app.put("/user/:id", verifyToken, async (req, res) => {
  try {
    const { id } = req.params;
    if (req.userId !== id) {
      const requester = await User.findById(req.userId);
      if (!requester || requester.role !== "admin") return res.status(403).json({ message: "Unauthorized" });
    }
    const updates = {};
    if (req.body.gameId) updates.gameId = String(req.body.gameId).trim();
    const updated = await User.findByIdAndUpdate(id, updates, { new: true }).select("-password");
    res.json({ message: "Updated", user: updated });
  } catch (err) { console.error("Update user error:", err); res.status(500).json({ message: "Server error" }); }
});

// Start server
app.listen(PORT, () => console.log(`🚀 Server listening on port ${PORT}`));

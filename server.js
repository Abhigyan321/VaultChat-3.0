import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import compression from "compression";
import hpp from "hpp";
import "dotenv/config";

const app = express();

// ────────────────────────────────────────────────────────────
// Crash on boot if any required env var is missing
// ────────────────────────────────────────────────────────────
const REQUIRED = [
  "FIREBASE_API_KEY",
  "FIREBASE_AUTH_DOMAIN",
  "FIREBASE_PROJECT_ID",
  "FIREBASE_STORAGE_BUCKET",
  "FIREBASE_MESSAGING_SENDER_ID",
  "FIREBASE_APP_ID",
  "FIREBASE_DATABASE_URL",
  "ALLOWED_ORIGINS",
];
for (const k of REQUIRED) {
  if (!process.env[k]) {
    console.error(`[FATAL] Missing required env var: ${k}`);
    process.exit(1);
  }
}

const ALLOWED_ORIGINS = process.env.ALLOWED_ORIGINS.split(",")
  .map(s => s.trim())
  .filter(Boolean);

// ────────────────────────────────────────────────────────────
// Server hardening: HSTS, CSP, no-sniff, no-frame, etc.
// ────────────────────────────────────────────────────────────
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: true,
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: [
          "'self'",
          "'unsafe-inline'", // required because the app uses an inline <script type="module">
          "https://www.gstatic.com",
        ],
        connectSrc: [
          "'self'",
          "https://firestore.googleapis.com",
          "https://*.firebaseio.com",
          "wss://*.firebaseio.com",
          "https://*.googleapis.com",
        ],
        imgSrc: ["'self'", "data:", "https://*.googleusercontent.com"],
        styleSrc: [
          "'self'",
          "'unsafe-inline'",
          "https://fonts.googleapis.com",
        ],
        fontSrc: ["'self'", "https://fonts.gstatic.com"],
        frameAncestors: ["'none'"],
        objectSrc: ["'none'"],
        baseUri: ["'self'"],
        formAction: ["'self'"],
      },
    },
    hsts: {
      maxAge: 31536000,
      includeSubDomains: true,
      preload: true,
    },
    referrerPolicy: { policy: "strict-origin-when-cross-origin" },
    crossOriginEmbedderPolicy: false,
    crossOriginResourcePolicy: { policy: "cross-origin" },
  })
);

app.disable("x-powered-by");
app.set("etag", false);

// ────────────────────────────────────────────────────────────
// CORS — explicit allow-list, no wildcards
// ────────────────────────────────────────────────────────────
app.use(
  cors({
    origin(origin, cb) {
      if (!origin) return cb(null, true); // same-origin
      if (ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
      return cb(new Error("CORS blocked"));
    },
    credentials: false,
    methods: ["GET"],
  })
);

// HPP — block duplicate query params
app.use(hpp());

// Compression
app.use(compression());

// JSON body limit (8 KB) — prevents payload bombs
app.use(express.json({ limit: "8kb" }));

// ────────────────────────────────────────────────────────────
// Rate limit on the config endpoint — 30 req/min/IP
// ────────────────────────────────────────────────────────────
const configLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: "Too many requests" },
});
app.use("/api/", configLimiter);

// ────────────────────────────────────────────────────────────
// In-memory cache (5 min) for the Firebase config payload
// ────────────────────────────────────────────────────────────
let configCache = { ts: 0, data: null };
const CACHE_TTL = 5 * 60 * 1000;

app.get("/api/app-config", (_req, res) => {
  const now = Date.now();
  if (!configCache.data || now - configCache.ts > CACHE_TTL) {
    configCache = {
      ts: now,
      data: {
        apiKey:            process.env.FIREBASE_API_KEY,
        authDomain:        process.env.FIREBASE_AUTH_DOMAIN,
        projectId:         process.env.FIREBASE_PROJECT_ID,
        storageBucket:     process.env.FIREBASE_STORAGE_BUCKET,
        messagingSenderId: process.env.FIREBASE_MESSAGING_SENDER_ID,
        appId:             process.env.FIREBASE_APP_ID,
        databaseURL:       process.env.FIREBASE_DATABASE_URL,
      },
    };
  }
  res.set("Cache-Control", "public, max-age=300");
  res.json(configCache.data);
});

// Health check (also useful for Render)
app.get("/healthz", (_req, res) => res.status(200).json({ ok: true }));

// 404
app.use((_req, res) => res.status(404).json({ error: "Not found" }));

// Generic error handler — logs only the message, never env or config values
app.use((err, _req, res, _next) => {
  console.error("[ERROR]", err.message);
  res.status(500).json({ error: "Server error" });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`VaultChat backend listening on port ${PORT}`);
});

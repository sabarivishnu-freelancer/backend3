const express = require("express");
const http = require("http");
const { Server } = require("socket.io");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const path = require("path");

const JWT_SECRET = process.env.JWT_SECRET || "dev_secret_change_me";

const app = express();
const server = http.createServer(app);

app.use(express.json({ limit: "50mb" }));
app.use(express.urlencoded({ limit: "50mb", extended: true }));
app.use(cors());

// serve static files (index.html)
app.use(express.static(path.join(__dirname)));

// initialize sqlite db
const db = new sqlite3.Database(path.join(__dirname, "database.sqlite"));

db.serialize(() => {
  db.run(
    `CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL
    )`,
  );

  db.run(
    `CREATE TABLE IF NOT EXISTS messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      sender_id INTEGER NOT NULL,
      receiver_id INTEGER NOT NULL,
      content TEXT NOT NULL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY (sender_id) REFERENCES users(id),
      FOREIGN KEY (receiver_id) REFERENCES users(id)
    )`,
  );
});

// helper: create JWT
function createToken(user) {
  return jwt.sign({ id: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: "7d",
  });
}

// auth middleware for express
function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).json({ error: "Missing Authorization" });
  const parts = authHeader.split(" ");
  if (parts.length !== 2 || parts[0] !== "Bearer")
    return res.status(401).json({ error: "Invalid Authorization" });
  const token = parts[1];
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ error: "Invalid token" });
  }
}

// Register
app.post("/register", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email and password are required" });

  const hashed = bcrypt.hashSync(password, 8);
  const stmt = db.prepare("INSERT INTO users (email, password) VALUES (?, ?)");
  stmt.run(email, hashed, function (err) {
    if (err) {
      if (err.code === "SQLITE_CONSTRAINT")
        return res.status(400).json({ error: "Email already registered" });
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }
    const user = { id: this.lastID, email };
    const token = createToken(user);
    res.json({ user, token });
  });
  stmt.finalize();
});

// Login
app.post("/login", (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password)
    return res.status(400).json({ error: "email and password are required" });

  db.get(
    "SELECT id, email, password FROM users WHERE email = ?",
    [email],
    (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      if (!row) return res.status(401).json({ error: "Invalid credentials" });
      const match = bcrypt.compareSync(password, row.password);
      if (!match) return res.status(401).json({ error: "Invalid credentials" });
      const user = { id: row.id, email: row.email };
      const token = createToken(user);
      res.json({ user, token });
    },
  );
});

// list users (for selecting a receiver)
app.get("/users", authMiddleware, (req, res) => {
  const me = req.user.id;
  db.all("SELECT id, email FROM users WHERE id != ?", [me], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: "Database error" });
    }
    res.json(rows || []);
  });
});

// get messages between authenticated user and another user
app.get("/messages/:withId", authMiddleware, (req, res) => {
  const me = req.user.id;
  const withId = Number(req.params.withId);
  db.all(
    `SELECT id, sender_id, receiver_id, content, created_at FROM messages
     WHERE (sender_id = ? AND receiver_id = ?) OR (sender_id = ? AND receiver_id = ?)
     ORDER BY created_at ASC`,
    [me, withId, withId, me],
    (err, rows) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: "Database error" });
      }
      res.json(rows || []);
    },
  );
});

const io = new Server(server, {
  cors: {
    origin: true,
    methods: ["GET", "POST"],
  },
});

// Map userId -> socket.id(s) handled by rooms 'user:<id>'
io.use((socket, next) => {
  const token = socket.handshake.auth && socket.handshake.auth.token;
  if (!token) return next(new Error("Authentication error"));
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    socket.user = decoded;
    return next();
  } catch (err) {
    return next(new Error("Authentication error"));
  }
});

io.on("connection", (socket) => {
  const userId = socket.user.id;
  console.log(`User connected: ${userId}`);
  // join a room for this user so we can emit to them by id
  socket.join(`user:${userId}`);

  socket.on("private_message", (payload) => {
    // payload: { to, content }
    const from = userId;
    const to = Number(payload.to);
    if (!to) return;

    // support two kinds of payloads from client:
    // 1) plain text messages: { to, content }
    // 2) protected messages: { to, encrypted, plain } where `encrypted` is the ciphertext
    // We'll store protected messages as a JSON envelope so clients can decide what to show
    // (the plain text is only stored as plain_for_sender so the sender can see it on reload).
    let contentToStore = null;
    if (payload && payload.encrypted) {
      const envelope = { encrypted: String(payload.encrypted) };
      if (payload.plain) envelope.plain_for_sender = String(payload.plain);
      contentToStore = JSON.stringify(envelope);
    } else {
      const content = String(payload.content || "");
      if (!content) return;
      contentToStore = content;
    }

    const stmt = db.prepare(
      "INSERT INTO messages (sender_id, receiver_id, content) VALUES (?, ?, ?)",
    );
    stmt.run(from, to, contentToStore, function (err) {
      if (err) {
        console.error("Failed to save message", err);
        return;
      }
      const message = {
        id: this.lastID,
        sender_id: from,
        receiver_id: to,
        content: contentToStore,
        created_at: new Date().toISOString(),
      };
      // Emit to receiver's room
      io.to(`user:${to}`).emit("private_message", message);
      // Emit back to sender as confirmation
      io.to(`user:${from}`).emit("private_message", message);
    });
    stmt.finalize();
  });

  socket.on("disconnect", () => {
    console.log(`User disconnected: ${userId}`);
  });
});

const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

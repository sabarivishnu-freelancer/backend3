const express = require("express");
const { Pool } = require("pg");
const bcrypt = require("bcrypt");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

// ✅ PostgreSQL connection (Render + Supabase)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

const PORT = process.env.PORT || 10000;

// ✅ Register
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  try {
    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      "INSERT INTO users (username, password) VALUES ($1, $2)",
      [username, hashedPassword]
    );

    res.json({ message: "User registered successfully" });
  } catch (err) {
    console.error(err); // ✅ Add this for debugging
    res.status(500).json({ error: "User already exists or DB error" });
  }
});

// ✅ Login
app.post("/login", async (req, res) => {
  const { username, password } = req.body;

  try {
    const result = await pool.query(
      "SELECT * FROM users WHERE username=$1",
      [username]
    );

    if (result.rows.length === 0) {
      return res.status(400).json({ error: "User not found" });
    }

    const user = result.rows[0];
    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ error: "Wrong password" });
    }

    res.json({ message: "Login successful" });
  } catch (err) {
    console.error(err); // ✅ Add this for debugging
    res.status(500).json({ error: "Login failed" });
  }
});

app.get("/", (req, res) => {
  res.send("Backend Running 🚀");
});
app.listen(PORT, () => {
  console.log(`Server running on ${PORT}`);
});

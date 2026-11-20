
const express = require("express");
const bcrypt = require("bcryptjs");
const session = require("express-session");
const path = require("path");

const {
  initializeDatabase,
  getDatabase,
  saveDatabase
} = require("./database");

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(express.json());

// Serve the EcoSlate website
app.use(express.static(path.join(__dirname, "..")));

// Session configuration
app.use(
  session({
    name: "ecoslate.sid",
    secret: process.env.SESSION_SECRET || "ecoslate-local-development-secret-change-this",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: false, // Localhost development only; use true with HTTPS in production
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 4
    }
  })
);


// -------------------------------------
// AUTHENTICATION MIDDLEWARE
// -------------------------------------

function requireLogin(req, res, next) {
  if (!req.session.user) {
    return res.status(401).json({
      message: "Please log in first."
    });
  }

  next();
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.session.user) {
      return res.status(401).json({
        message: "Please log in first."
      });
    }

    if (req.session.user.role !== role) {
      return res.status(403).json({
        message: "You do not have permission to access this feature."
      });
    }

    next();
  };
}


// -------------------------------------
// HOME AND STATUS
// -------------------------------------

app.get("/", (req, res) => {
  res.send("🌿 Welcome to the EcoSlate Backend!");
});

app.get("/api/status", (req, res) => {
  res.json({
    project: "EcoSlate",
    status: "Running successfully"
  });
});


// -------------------------------------
// STUDENT REGISTRATION
// -------------------------------------

app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({
        message: "Please fill in all fields."
      });
    }

    if (
      typeof name !== "string" ||
      typeof email !== "string" ||
      typeof password !== "string"
    ) {
      return res.status(400).json({
        message: "Invalid registration details."
      });
    }

    const cleanName = name.trim();
    const cleanEmail = email.trim().toLowerCase();

    if (cleanName.length < 2 || cleanName.length > 60) {
      return res.status(400).json({
        message: "Name must be between 2 and 60 characters."
      });
    }

    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

    if (!emailPattern.test(cleanEmail)) {
      return res.status(400).json({
        message: "Please enter a valid email."
      });
    }

    if (password.length < 8 || password.length > 72) {
      return res.status(400).json({
        message: "Password must be between 8 and 72 characters."
      });
    }

    const db = getDatabase();

    const check = db.prepare(
      "SELECT id FROM users WHERE email = ?"
    );

    check.bind([cleanEmail]);

    const alreadyExists = check.step();

    check.free();

    if (alreadyExists) {
      return res.status(409).json({
        message: "This email is already registered."
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    db.run(
      `INSERT INTO users (name, email, password_hash, role)
       VALUES (?, ?, ?, ?)`,
      [cleanName, cleanEmail, passwordHash, "student"]
    );

    saveDatabase();

    res.status(201).json({
      message: "Student account created successfully!"
    });

  } catch (error) {
    console.error("Registration error:", error);

    res.status(500).json({
      message: "Registration failed. Please try again."
    });
  }
});


// -------------------------------------
// LOGIN
// -------------------------------------

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (
      typeof email !== "string" ||
      typeof password !== "string" ||
      !email.trim() ||
      !password
    ) {
      return res.status(400).json({
        message: "Please enter your email and password."
      });
    }

    const cleanEmail = email.trim().toLowerCase();
    const db = getDatabase();

    const query = db.prepare(
      `SELECT id, name, email, password_hash, role
       FROM users WHERE email = ?`
    );

    query.bind([cleanEmail]);

    let user = null;

    if (query.step()) {
      user = query.getAsObject();
    }

    query.free();

    if (!user) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    const passwordMatches = await bcrypt.compare(
      password,
      user.password_hash
    );

    if (!passwordMatches) {
      return res.status(401).json({
        message: "Invalid email or password."
      });
    }

    // Regenerate session after successful login
    req.session.regenerate((error) => {
      if (error) {
        console.error("Session error:", error);

        return res.status(500).json({
          message: "Could not start your session."
        });
      }

      req.session.user = {
        id: user.id,
        name: user.name,
        email: user.email,
        role: user.role
      };

      req.session.save((saveError) => {
        if (saveError) {
          console.error("Session save error:", saveError);

          return res.status(500).json({
            message: "Could not save your session."
          });
        }

        res.json({
          message: "Login successful!",
          user: req.session.user
        });
      });
    });

  } catch (error) {
    console.error("Login error:", error);

    res.status(500).json({
      message: "Login failed. Please try again."
    });
  }
});


// -------------------------------------
// CURRENT LOGGED-IN USER
// -------------------------------------

app.get("/api/me", requireLogin, (req, res) => {
  res.json({
    user: req.session.user
  });
});


// -------------------------------------
// LOGOUT
// -------------------------------------

app.post("/api/logout", requireLogin, (req, res) => {
  req.session.destroy((error) => {
    if (error) {
      console.error("Logout error:", error);

      return res.status(500).json({
        message: "Logout failed."
      });
    }

    res.clearCookie("ecoslate.sid");

    res.json({
      message: "Logged out successfully."
    });
  });
});


// -------------------------------------
// TEACHER-ONLY TEST ROUTE
// -------------------------------------

app.get(
  "/api/teacher/access",
  requireRole("teacher"),
  (req, res) => {
    res.json({
      message: "Teacher access granted!",
      teacher: req.session.user
    });
  }
);


// -------------------------------------
// STUDENT-ONLY TEST ROUTE
// -------------------------------------

app.get(
  "/api/student/access",
  requireRole("student"),
  (req, res) => {
    res.json({
      message: "Student access granted!",
      student: req.session.user
    });
  }
);


// -------------------------------------
// START SERVER
// -------------------------------------

async function startServer() {
  await initializeDatabase();

  app.listen(PORT, () => {
    console.log(
      `EcoSlate server running at http://localhost:${PORT}`
    );
  });
}

startServer().catch((error) => {
  console.error("Could not start EcoSlate:", error);
});

const express = require("express");
const cors = require("cors");
// const mysql = require("mysql2");
const db = require("./db"); 

const bcrypt = require("bcryptjs");
const bodyParser = require("body-parser");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const jwt = require("jsonwebtoken");

const JWT_SECRET = "my_jwt_secret_key";

const app = express();
app.use(cors());
app.use(bodyParser.json());

// Serve uploaded images
app.use("/uploads", express.static("uploads"));

// Create uploads folder if not exists
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads/"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname)),
});
const upload = multer({ storage });

// MySQL setup
// const db = mysql.createConnection({
//   host: "localhost",
//   user: "root",
//   password: "",
//   database: "user_authntication",
// });

// db.connect((err) => {
//   if (err) console.error("❌ DB connection failed:", err);
//   else console.log("✅ MySQL Connected");
// });

// JWT Middleware
function verifyToken(req, res, next) {
  const token = req.headers["authorization"];
  if (!token)
    return res
      .status(401)
      .json({ success: false, message: "No token provided" });

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err)
      return res.status(401).json({ success: false, message: "Invalid token" });
    req.user = decoded;
    next();
  });
}

// GET all users
app.get("/users", (req, res) => {
  const sql = "SELECT * FROM user_new_data";
  db.query(sql, (err, result) => {
    if (err) return res.json({ error: err });
    return res.json(result);
  });
});

// REGISTER
app.post("/register", upload.single("user_image"), (req, res) => {
  const { user_name, user_phonenum, user_email, user_password } = req.body;
  const imagePath = req.file ? req.file.filename : null;

  if (!user_name || !user_phonenum || !user_email || !user_password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields are required" });
  }

  db.query(
    "SELECT * FROM user_new_data WHERE user_email = ?",
    [user_email],
    (err, results) => {
      if (err)
        return res.status(500).json({ success: false, message: "DB error" });

      if (results.length > 0) {
        return res
          .status(400)
          .json({ success: false, message: "Email already registered" });
      }

      const hashedPassword = bcrypt.hashSync(user_password, 10);
      const sql =
        "INSERT INTO user_new_data (user_name, user_phonenum, user_email, user_password, user_image) VALUES (?, ?, ?, ?, ?)";

      db.query(
        sql,
        [user_name, user_phonenum, user_email, hashedPassword, imagePath],
        (err) => {
          if (err)
            return res
              .status(500)
              .json({ success: false, message: "Insert error" });

          res
            .status(201)
            .json({ success: true, message: "Registered successfully" });
        }
      );
    }
  );
});

// LOGIN
app.post("/login", (req, res) => {
  const { user_email, user_password } = req.body;

  if (!user_email || !user_password) {
    return res
      .status(400)
      .json({ success: false, message: "All fields required" });
  }

  db.query(
    "SELECT * FROM user_new_data WHERE user_email = ?",
    [user_email],
    (err, results) => {
      if (err)
        return res.status(500).json({ success: false, message: "DB error" });

      if (results.length === 0) {
        return res
          .status(400)
          .json({ success: false, message: "User not found" });
      }

      const user = results[0];
      const isPasswordValid = bcrypt.compareSync(
        user_password,
        user.user_password
      );

      if (!isPasswordValid) {
        return res
          .status(401)
          .json({ success: false, message: "Invalid password" });
      }

      const token = jwt.sign(
        { id: user.id, email: user.user_email },
        JWT_SECRET,
        { expiresIn: "2h" }
      );

      res.status(200).json({
        success: true,
        message: "Login successful",
        token,
        user: {
          id: user.id,
          name: user.user_name,
          email: user.user_email,
          phone: user.user_phonenum,
          image: user.user_image
            ? `http://localhost:5000/uploads/${user.user_image}`
            : null,
        },
      });
    }
  );
});

// ✅ PROTECTED ROUTE - ADDRESS INSERT
app.post("/address", verifyToken, (req, res) => {
  const { address_line, city, state, pincode, country, mobile_num } = req.body;
  const user_id = req.user.id;

  if (!address_line || !city || !state || !pincode || !country || !mobile_num) {
    return res
      .status(400)
      .json({ success: false, message: "All fields required" });
  }

  const sql =
    "INSERT INTO user_address (user_id, address_line, city, state, pincode, country, mobile_num) VALUES (?, ?, ?, ?, ?, ?, ?)";

  db.query(
    sql,
    [user_id, address_line, city, state, pincode, country, mobile_num],
    (err) => {
      if (err) {
        console.error("❗ Address insertion error:", err);
        return res
          .status(500)
          .json({ success: false, message: "Database error" });
      }
      res
        .status(201)
        .json({ success: true, message: "Address saved successfully" });
    }
  );
});

// GET ADDRESS BY USER_ID
app.get("/address/:user_id", (req, res) => {
  const { user_id } = req.params;
  const sql = "SELECT * FROM user_address WHERE user_id = ?";
  db.query(sql, [user_id], (err, result) => {
    if (err) {
      console.error("❌ Failed to fetch addresses:", err);
      return res.status(500).json({ success: false, message: "DB error" });
    }
    res.status(200).json({ success: true, data: result });
  });
});

// Health check
app.get("/", (req, res) => res.send("✅ Backend working"));

app.listen(5000, () => console.log("🚀 Server running on port 5000"));

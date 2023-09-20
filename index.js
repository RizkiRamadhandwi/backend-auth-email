const express = require("express");
const mongoose = require("mongoose");
const bodyParser = require("body-parser");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const session = require("express-session");
const dotenv = require("dotenv");
const cors = require("cors");
const nodemailer = require("nodemailer");
const dashboard = require("./routes/dashboard_route.js");

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Membaca data dari body request
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Mengizinkan akses dari semua domain
app.use(cors());

// Atau, jika Anda ingin membatasi akses hanya ke beberapa domain tertentu, gunakan kode berikut:
// Ganti 'http://example.com' dengan domain yang ingin Anda izinkan
// app.use(cors({ origin: 'http://example.com' }));

// Koneksi ke MongoDB
mongoose
  .connect(process.env.MONGODB_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => {
    console.log("Connected to MongoDB");
  })
  .catch((error) => {
    console.error("Failed to connect to MongoDB:", error);
  });

// Definisikan user schema
const userSchema = new mongoose.Schema({
  namaLengkap: {
    type: String,
    required: true,
  },
  email: {
    type: String,
    required: true,
    unique: true,
  },
  password: {
    type: String,
    required: true,
  },
  url_photo: {
    type: String,
    default: "/public/images/user_default.png",
  },
});

const User = mongoose.model("User", userSchema);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Konfigurasi session
app.use(
  session({
    secret: "secret-key",
    resave: false,
    saveUninitialized: false,
  })
);

// Mengirim email verifikasi
const sendVerificationEmail = async (email) => {
  const transporter = nodemailer.createTransport({
    service: "Gmail",
    auth: {
      user: process.env.GMAIL_USERNAME,
      pass: process.env.GMAIL_PASSWORD,
    },
  });

  const mailOptions = {
    from: "noreply@example.com",
    to: email,
    subject: "Verifikasi Email",
    text: "Anda telah berhasil terdaftar. Silakan verifikasi email Anda.",
  };

  try {
    await transporter.sendMail(mailOptions);
    console.log("Email verifikasi telah dikirim.");
  } catch (error) {
    console.log("Terjadi kesalahan saat mengirim email verifikasi:", error);
  }
};

// Route untuk register
app.post("/register", async (req, res) => {
  try {
    const { namaLengkap, email, password } = req.body;

    // Hash password menggunakan bcrypt
    const hashedPassword = await bcrypt.hash(password, 10);

    // Buat user baru
    const user = new User({
      namaLengkap,
      email,
      password: hashedPassword,
    });

    // Simpan user ke database
    await user.save();

    await sendVerificationEmail(email);

    res.status(201).json({
      message:
        "Registrasi berhasil. Silakan periksa email Anda untuk verifikasi.",
    });
  } catch (error) {
    console.log("Terjadi kesalahan saat registrasi:", error);
    res.status(500).json({ message: "Terjadi kesalahan saat registrasi." });
  }
});

// Route untuk login
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;
    console.log(email, password);

    // Cari user berdasarkan email
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Bandingkan password yang dimasukkan dengan password di database menggunakan bcrypt
    const isPasswordValid = await bcrypt.compare(password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid email or password" });
    }

    // Buat JWT token
    const token = jwt.sign(
      {
        userId: user._id,
        roles: "admin",
        name: "admin",
        avatar: "tes",
        introduction: "tes",
      },
      "secret-key"
    );

    // Simpan token di session
    req.session.token = token;
    console.log("success", token);
    res.json({ data: { token, message: "success" } });
  } catch (error) {
    console.log("error: " + error);
    res.status(500).json({ error: "Failed to login" });
  }
});

// Middleware untuk memeriksa token di setiap request yang membutuhkan autentikasi
const authenticateToken = (req, res, next) => {
  const token = req.session.token;

  if (!token) {
    return res.status(401).json({ error: "Unauthorized" });
  }

  try {
    // Verifikasi token menggunakan JWT
    const decoded = jwt.verify(token, "secret-key");

    // Set userId di objek request
    req.userId = decoded.userId;

    next();
  } catch (error) {
    res.status(401).json({ error: "Invalid token" });
  }
};

// Route untuk mendapatkan informasi user yang sedang login
app.get("/user", authenticateToken, async (req, res) => {
  try {
    // Dapatkan ID user dari token yang telah divalidasi
    const userId = req.userId;

    // Cari user berdasarkan ID
    const user = await User.findById(userId);

    // Jika user tidak ditemukan
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Kirim informasi user yang sedang login
    res.json({ user });
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Contoh route yang membutuhkan autentikasi
app.get("/protected", authenticateToken, (req, res) => {
  res.json({ message: "Protected route accessed successfully" });
});

// Route untuk logout
app.post("/logout", (req, res) => {
  // Hapus token dari session
  delete req.session.token;

  res.json({ message: "Logged out successfully" });
});

app.use("/dashboard", dashboard);

// Jalankan server
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});

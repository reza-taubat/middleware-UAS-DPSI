const jwt = require("jsonwebtoken"); // Mengimpor modul jsonwebtoken untuk bekerja dengan JSON Web Tokens (JWT)
require("dotenv").config(); // Mengimpor dan mengkonfigurasi dotenv untuk memuat variabel lingkungan dari file .env

// Mengimpor model User dari direktori models
const User = require("../models/User");

// Middleware untuk autentikasi token JWT
const authenticateToken = async (req, res, next) => {
  // Mengambil header authorization dari request
  const authHeader = req.headers["authorization"];

  // Mengekstrak token dari header authorization (format: "Bearer token")
  const token = authHeader && authHeader.split(" ")[1];

  // Jika token tidak ada, kirimkan status 401 Unauthorized
  if (!token) return res.sendStatus(401);

  try {
    // Memverifikasi token menggunakan ACCESS_TOKEN_SECRET dari variabel lingkungan
    const decoded = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);

    // Mencari user berdasarkan userId yang diambil dari token
    const user = await User.findByPk(decoded.userId);

    // Jika user tidak ditemukan, kirimkan status 403 Forbidden
    if (!user) return res.sendStatus(403);

    // Menyimpan informasi user ke dalam req.user untuk digunakan oleh middleware berikutnya
    req.user = { id: user.id, role: user.role };

    // Melanjutkan ke middleware berikutnya
    next();
  } catch (error) {
    // Jika terjadi error saat verifikasi token, kirimkan status 403 Forbidden
    res.sendStatus(403);
  }
};

// Middleware untuk otorisasi berdasarkan role
const authorizeRole = (role) => (req, res, next) => {
  // Memeriksa apakah role dari req.user sesuai dengan role yang diperlukan
  if (req.user.role !== role) {
    // Jika role tidak sesuai, kirimkan status 403 Forbidden dengan pesan
    return res.status(403).json({ message: "Forbidden" });
  }

  // Jika role sesuai, lanjutkan ke middleware berikutnya
  next();
};

// Mengekspor middleware untuk digunakan di tempat lain
module.exports = { authenticateToken, authorizeRole };

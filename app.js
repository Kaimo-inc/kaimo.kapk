const express = require("express");
const crypto = require("crypto");
const multer = require("multer");
const app = express();

// Sabit anahtar ve IV (Şifreleme ve şifre çözme için tutarlı)
const SECRET_KEY = Buffer.from("8b5ef8fe4f6d04c8f107dd951eeb8c622b0845b34f6d8909f0a017462a5a9f00", "hex");
const IV = Buffer.from("fa7b3489de1c47d07f9abfc4dbfd57f9", "hex");

const upload = multer({
  limits: { fileSize: 1024 * 1024 * 1024 }, // Maksimum dosya boyutu 1 GB
  fileFilter: (req, file, cb) => {
    const allowedExtensions = ['.apk', '.kapk'];
    if (!allowedExtensions.some(ext => file.originalname.endsWith(ext))) {
      return cb(new Error("Sadece .apk ve .kapk dosyaları yüklenebilir!"));
    }
    cb(null, true);
  },
});

app.set("view engine", "ejs");
app.use(express.static("public"));

function encryptBuffer(buffer) {
  const cipher = crypto.createCipheriv("aes-256-cbc", SECRET_KEY, IV);
  return Buffer.concat([cipher.update(buffer), cipher.final()]);
}

function decryptBuffer(buffer) {
  const decipher = crypto.createDecipheriv("aes-256-cbc", SECRET_KEY, IV);
  return Buffer.concat([decipher.update(buffer), decipher.final()]);
}

app.get("/", (req, res) => {
  res.render("index");
});

app.get('/kapk', (req, res) => {
  res.render('kapk');
});

app.post("/encrypt", upload.single("file"), (req, res) => {
  try {
    const encryptedBuffer = encryptBuffer(req.file.buffer);
    res.setHeader("Content-Disposition", `attachment; filename=${req.file.originalname}.kapk`);
    res.setHeader("Content-Type", "application/octet-stream");
    res.send(encryptedBuffer);
  } catch (err) {
    res.status(500).send("Şifreleme işlemi sırasında bir hata oluştu.");
  }
});

app.post("/decrypt", upload.single("file"), (req, res) => {
  try {
    const decryptedBuffer = decryptBuffer(req.file.buffer);
    res.setHeader("Content-Disposition", `attachment; filename=${req.file.originalname.replace(".kapk", ".apk")}`);
    res.setHeader("Content-Type", "application/vnd.android.package-archive");
    res.send(decryptedBuffer);
  } catch (err) {
    res.status(400).send("Şifre çözme işlemi başarısız oldu!");
  }
});

app.listen(3000, () => {
  console.log("Sunucu 3000 portunda çalışıyor");
});

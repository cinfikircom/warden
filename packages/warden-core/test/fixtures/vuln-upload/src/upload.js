const express = require("express");
const multer = require("multer");
const fs = require("fs");
const path = require("path");
const router = express.Router();

// UPLOAD-1: fileFilter yok (kısıtsız tip). UPLOAD-3: limits yok. UPLOAD-4: web-root'ta dest.
const upload = multer({ dest: "public/uploads" });

router.post("/avatar", upload.single("file"), async (req, res) => {
  // UPLOAD-2: kullanıcı adı (originalname) doğrudan yola giriyor, basename/sanitize yok.
  const target = path.join("public/uploads", req.file.originalname);
  fs.writeFileSync(target, fs.readFileSync(req.file.path));
  res.json({ url: "/uploads/" + req.file.originalname });
});

module.exports = router;

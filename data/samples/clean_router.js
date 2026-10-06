const express = require("express");
const router = express.Router();

router.get("/health", (req, res) => {
  res.json({ status: "ok", uptime: process.uptime() });
});

router.get("/version", (req, res) => {
  res.json({ version: process.env.APP_VERSION || "dev" });
});

module.exports = router;

const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.get("/search", (req, res) => {
  const q = String(req.query.q || "");
  res.send("<h1>Results for " + escapeHtml(q) + "</h1>");
});

app.listen(3000);

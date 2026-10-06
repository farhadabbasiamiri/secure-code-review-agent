const express = require("express");
const mysql = require("mysql2");
const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop" });
const app = express();

app.get("/products/:id", (req, res) => {
  const id = Number.parseInt(req.params.id, 10);
  if (!Number.isInteger(id)) return res.status(400).send("bad id");
  db.query("SELECT * FROM products WHERE id = ?", [id], (err, rows) => {
    if (err) return res.status(500).send("error");
    res.json(rows);
  });
});

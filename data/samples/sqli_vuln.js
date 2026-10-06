const express = require("express");
const mysql = require("mysql2");
const db = mysql.createConnection({ host: "localhost", user: "app", database: "shop" });
const app = express();

app.get("/products/:id", (req, res) => {
  const sql = "SELECT * FROM products WHERE id = " + req.params.id;
  db.query(sql, (err, rows) => {
    if (err) return res.status(500).send("error");
    res.json(rows);
  });
});

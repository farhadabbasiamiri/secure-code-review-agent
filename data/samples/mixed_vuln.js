const express = require("express");
const { exec } = require("child_process");
const app = express();
app.use(express.json());

const API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyzAB";

app.get("/hello", (req, res) => {
  res.send(`<p>Hi ${req.query.name}</p>`);
});

app.post("/backup", (req, res) => {
  exec("tar -czf /backups/" + req.body.name + ".tgz /data");
  res.cookie("last_backup", req.body.name);
  res.send("ok");
});

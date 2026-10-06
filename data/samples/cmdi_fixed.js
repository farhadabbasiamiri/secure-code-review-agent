const express = require("express");
const { execFile } = require("child_process");
const net = require("net");
const app = express();

app.get("/ping", (req, res) => {
  const host = String(req.query.host || "");
  if (!net.isIP(host)) return res.status(400).send("invalid host");
  execFile("ping", ["-c", "1", host], (err, stdout) => {
    res.type("text").send(stdout);
  });
});

const express = require("express");
const escapeHtml = require("escape-html");
const { execFile } = require("child_process");
const app = express();

app.get("/greet", (req, res) => {
  res.send("<p>Hello " + escapeHtml(req.query.name) + "</p>");
});

app.get("/ping", (req, res) => {
  execFile("ping", ["-c", "1", String(req.query.host)], (err, out) => res.type("text").send(out));
});

function firstNumber(text) {
  const m = /(\d+)/.exec(text);
  return m ? Number(m[1]) : null;
}

module.exports = { app, firstNumber };

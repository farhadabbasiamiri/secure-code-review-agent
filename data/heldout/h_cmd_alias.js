const child = require("child_process");
const express = require("express");
const app = express();
app.use(express.json());

app.post("/convert", (req, res) => {
  child.exec("convert " + req.body.file + " out.png", (err) => {
    res.send(err ? "failed" : "done");
  });
});

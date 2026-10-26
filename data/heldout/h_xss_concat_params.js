const express = require("express");
const app = express();

app.get("/user/:name", (req, res) => {
  res.send("<h2>Profile of " + req.params.name + "</h2>");
});

module.exports = app;

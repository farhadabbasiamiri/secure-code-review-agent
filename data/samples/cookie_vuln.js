const express = require("express");
const app = express();

app.post("/login", (req, res) => {
  const token = createSessionToken(req.body.user);
  res.cookie("session", token);
  res.cookie("remember", token, { httpOnly: false, secure: false });
  res.redirect("/");
});

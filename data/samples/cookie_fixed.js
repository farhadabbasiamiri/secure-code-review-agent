const express = require("express");
const app = express();

app.post("/login", (req, res) => {
  const token = createSessionToken(req.body.user);
  res.cookie("session", token, { httpOnly: true, secure: true, sameSite: "strict" });
  res.redirect("/");
});

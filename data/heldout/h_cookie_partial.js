const express = require("express");
const app = express();
app.use(express.json());

app.post("/prefs", (req, res) => {
  res.cookie("sid", req.body.sessionId, { httpOnly: true });
  res.cookie("lang", "en", { secure: true, httpOnly: true, sameSite: "strict" });
  res.end();
});

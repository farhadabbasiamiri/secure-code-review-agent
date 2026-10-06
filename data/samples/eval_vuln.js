const express = require("express");
const app = express();
app.use(express.json());

app.post("/calc", (req, res) => {
  const result = eval(req.body.expression);
  res.json({ result });
});

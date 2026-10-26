const express = require("express");
const User = require("./models/user");
const app = express();
app.use(express.json());

app.put("/profile", async (req, res) => {
  const user = await User.findById(req.session.userId);
  Object.assign(user, req.body);
  await user.save();
  res.json(user);
});

const express = require("express");
const { z } = require("zod");
const User = require("./models/user");
const app = express();
app.use(express.json());

const NewUser = z.object({ email: z.string().email(), name: z.string().min(1).max(80) });

app.post("/users", async (req, res) => {
  const parsed = NewUser.safeParse(req.body);
  if (!parsed.success) return res.status(400).json(parsed.error.flatten());
  const user = await User.create(parsed.data);
  res.status(201).json(user);
});

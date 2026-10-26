const express = require("express");
const Item = require("./models/item");
const app = express();
app.use(express.json());

app.patch("/items/:id", async (req, res) => {
  const item = await Item.findOneAndUpdate({ _id: req.params.id }, req.body, { new: true });
  res.json(item);
});

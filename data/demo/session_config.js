const express = require("express");
const session = require("express-session");
const app = express();

app.use(session({ secret: process.env.SESSION_SECRET, cookie: { httpOnly: false, secure: false } }));

app.get("/", (req, res) => res.send("ok"));

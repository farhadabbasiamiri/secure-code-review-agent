const jwt = require("jsonwebtoken");
const AWS = require("aws-sdk");

const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) throw new Error("JWT_SECRET not set");
const s3 = new AWS.S3();

function sign(user) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "1h" });
}

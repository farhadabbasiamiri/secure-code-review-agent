const jwt = require("jsonwebtoken");
const AWS = require("aws-sdk");

const JWT_SECRET = "super-secret-signing-key-123";
const s3 = new AWS.S3({
  accessKeyId: "AKIAIOSFODNN7EXAMPLE",
  secretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
});

function sign(user) {
  return jwt.sign({ sub: user.id }, JWT_SECRET, { expiresIn: "1h" });
}

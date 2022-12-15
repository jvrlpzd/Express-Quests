const argon2 = require("argon2");
const jwt = require("jsonwebtoken");
const JWT_SECRET = process.env.JWT_SECRET

const hashingOptions = {
  type: argon2.argon2id,
  memoryCost: 2 ** 16,
  timeCost: 5,
  parallelism: 1,
};

const hashPassword = (req, res, next) => {
  argon2
    .hash(req.body.password, hashingOptions)
    .then((hashedPassword) => {
      console.log(hashedPassword);

      req.body.hashedPassword = hashedPassword;

      delete req.body.password;

      next();
    })
    .catch((err) => {
      console.error(err);

      res.sendStatus(400);
    });
};

const verifyPassword = (req, res) => {
  argon2
    .verify(req.user.hashedPassword, req.body.password)
    .then((isVerified) => {
      if (isVerified) {
        const payload = { sub: req.user.id };
        const token = jwt.sign(payload , JWT_SECRET, { algorithm: 'HS512', expiresIn: "1h"});
        res.send(token);
      } else {
        res.sendStatus(401);
      }
    })
    .catch((err) => {
      console.error(err);
      res.sendStatus(500);
    });
};

// ...

const verifyToken = (req, res, next) => {
  try {
      const authHeader = req.headers.authorization;
      const [type, token] = authHeader.split(" ")
      if(type !== "Bearer") throw new Error("Only Bearer token allowed")
      req.payloads = jwt.verify(token, JWT_SECRET)

    next();
  } catch (err) {
    console.error(err);
    res.sendStatus(401);
  }
};

module.exports = {
  hashPassword,
  verifyPassword,
  verifyToken, // don't forget to export
};
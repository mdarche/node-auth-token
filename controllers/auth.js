const jwt = require("jwt-simple");
const User = require("../models/user");
const config = require("../config");

function tokenForUser(user) {
  const timestamp = new Date().getTime();
  return jwt.encode({ sub: user.id, iat: timestamp }, config.secret);
}

// MARK - Log In Controller
exports.login = function(req, res, next) {
  res.send({ token: tokenForUser(req.user) });
};

// MARK - Sign Up controller
exports.signup = function(req, res, next) {
  const email = req.body.email;
  const password = req.body.password;

  if (!email || !password) {
    return res
      .status(422)
      .send({ error: "You must provide a email and password" });
  }

  User.findOne({ email: email }, function(err, existingUser) {
    // Return error
    if (err) {
      return next(err);
    }

    // User exists
    if (existingUser) {
      return res.status(422).send({ error: "Email is in use" });
    }

    // Create new User
    const user = new User({
      email: email,
      password: password
    });

    user.save(function(err) {
      if (err) {
        return next(err);
      }
      res.json({ token: tokenForUser(user) });
    });
  });
};

const passport = require("passport");
const JwtStrategy = require("passport-jwt").Strategy;
const ExtractJwt = require("passport-jwt").ExtractJwt;
const LocalStrategy = require("passport-local");
const User = require("../models/user");
const config = require("../config");

// MARK - Local Passport Strategy

const localOptions = { usernameField: "email" };

const localLogin = new LocalStrategy(localOptions, function(
  email,
  password,
  done
) {
  User.findOne({ email: email }, function(err, user) {
    // Handle error
    if (err) {
      return done(err);
    }

    // No user found
    if (!user) {
      return done(null, false);
    }

    // Compare passwords
    user.comparePassword(password, function(err, isMatch) {
      if (err) {
        return done(err);
      }

      if (!isMatch) {
        return done(null, false);
      }

      return done(null, user);
    });
  });
});

// MARK - JWT Passport Strategy

const jwtOptions = {
  jwtFromRequest: ExtractJwt.fromHeader("authorization"),
  secretOrKey: config.secret
};

const jwtLogin = new JwtStrategy(jwtOptions, function(payload, done) {
  User.findById(payload.sub, function(err, user) {
    // Handle error
    if (err) {
      return done(err, false);
    }

    // Check for user
    if (user) {
      done(null, user);
    } else {
      done(null, false);
    }
  });
});

// Use strategies

passport.use(jwtLogin);
passport.use(localLogin);

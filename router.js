const Authentication = require("./controllers/auth");
const passportServce = require("./services/passport");
const passport = require("passport");

const requireAuth = passport.authenticate("jwt", { session: false });
const requireLogin = passport.authenticate("local", { session: false });

module.exports = function(app) {
  app.get("/", requireAuth, function(req, res) {
    res.send({ authenticated: "yes" });
  });
  app.post("/login", requireLogin, Authentication.login);
  app.post("/signup", Authentication.signup);
};

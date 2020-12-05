const jwt = require("jsonwebtoken")

module.exports = function(req,res,next) {
    if(req.headers.authorization == null) {
      return next()
    }

    converted = req.headers.authorization.replace(/%20/g, " ");
    var words = converted.split(' ')

    jwt.verify(words[1],"secret", (err,auth) => {
    if(!err) {
        req.username = auth.user;
        return next();
      }
    else {
        return res.status(401).json({"Error": "Access Denied"});
    }
  })
};
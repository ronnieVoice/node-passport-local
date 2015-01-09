var User = require('../models/user');
var passport = require('passport');
var LocalStrategy = require('passport-local').Strategy;
// seed a user
var user = new User({
	username: String,
	email: String,
	password: String
});
user.save(function(err, user){
	if(err) {
		console.log(err);
	} else {
		console.log('Seedy user');
	}
});

//session serialization
passport.serializeUser(function(user, next){
	// convert user object to session-storing id
	next(null, user._id);
});
passport.deserializeUser(function(id, next){
	// convert session-stored id into a user obj
	User.findById(id, function(err, user){
		next(err, user);
	});
});

// ensure authentication method
module.exports = {
	ensureAuthenticated: function(req, res, next){
		if(req.isAuthenticated()){
			return next();
		}
		res.redirect('/auth/login');
	}
};


// STRATEGIES:
var localStrategy = new LocalStrategy(
	function(username, password, next){
		User.findOne(
			{username: username},
			function(err, user){
				if(err){
					return next(err);
				}
				if(!user){
					return next(null, false);
				}

				// username matches a db document
				user.comparePassword(password,
				function(err, isMatch){
					if(err){
						return next(err);
					}
					if(isMatch){
						return next(null, user);
					} else {
						return next(null, false);
					}
				});
		});
	}
);

passport.use(localStrategy);
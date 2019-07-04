const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = function (config, app) {

	//console.log(app);

	passport.use(new GoogleStrategy({
			clientID: config.login.clientID,
			clientSecret: config.login.clientSecret,
			callbackURL: config.login.fullCallbackURL
		},
		function (accessToken, refreshToken, profile, done) {
			done(null, {
				profile: profile,
				domain: profile._json.domain
			});
		}
	));

	app.use(config.login.callbackURL, passport.initialize());
	app.use(config.login.callbackURL, passport.session());

	app.get(config.login.loginURL,
		passport.authenticate('google', {
			scope: config.scope
		})
	);

	if (config.forwardLogin === false) {
		app.get(config.loginURL, function (req, res, next) {
			req.internalURL = true;
			res.render('login');
		})
	}

	app.get(config.login.callbackURL,
		passport.authenticate('google', {
			failureRedirect: config.loginURL
		}),
		function (req, res) {
			res.redirect(config.homePath);
		}
	);

	app.get(config.logoutURL, function (req, res, next) {
		req.internalURL = true;
		req.session.destroy();
		req.logout();
		res.redirect(config.loginURL);
	});

	app.use(config.secureNamespace, function (req, res, next) {
		if (!req.user) {
			if (config.allowUnauthorized !== true && req.internalURL !== true) {
				res.redirect(config.loginURL);
			} else {
				next();
			}
		} else {
			next();
		}
	});

	// return (req, res, cb) => {
	//
	// 	app.use(function (err, req, res, next) {
	// 		if (err instanceof HttpForbidden) {
	// 			req.session.destroy();
	// 			req.logout();
	// 		}
	// 		cb(err, req, res);
	// 	});
	//
	// 	app.use(function (req, res, next) {
	// 		if (req.user) {
	// 			res.proxyHeaders.push([config.headerName, JSON.stringify(req.user)]);
	// 		}
	// 		cb(null, req, res);
	// 	});
	//
	// 	app(req, res)
	// }
};

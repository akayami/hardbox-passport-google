const express = require('express');
const session = require('express-session');
const ejs = require('ejs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;

module.exports = function(config) {

	return function(req, res, cb) {
		const express = require('express');
		const app = express();

		if (config.session.storeConf) {
			const sessionStore = require(config.session.storeConf.type)(session);
			config.session.store = new sessionStore(config.session.storeConf.config);
		}

		app.use(session(config.session));

		app.use(config.secureNamespace, passport.initialize());
		app.use(config.secureNamespace, passport.session());

		passport.serializeUser(function(user, done) {
			done(null, user);
		});

		passport.deserializeUser(function(user, done) {
			if (!config.google.allowedDomains || config.google.allowedDomains.includes(user.domain)) {
				done(null, user);
			} else {
				done(new HttpForbidden('Domain mismatch: ' + user.domain + ' not in ' + config.google.allowedDomains))
			}
		});

		app.set('view engine', 'ejs');


		if (config.forwardLogin === false) {
			app.get('/login', function(req, res, next) {
				res.render('login');
			})
		}

		passport.use(new GoogleStrategy({
				clientID: config.google.login.clientID,
				clientSecret: config.google.login.clientSecret,
				callbackURL: config.google.login.callbackURL
			},
			function(accessToken, refreshToken, profile, done) {
				done(null, {
					profile: profile,
					domain: profile._json.domain
				});
			}
		));

		app.get(config.google.login.loginURL,
			passport.authenticate('google', {
				scope: config.google.scope
			})
		);

		app.get(config.google.login.callbackURL,
			passport.authenticate('google', {
				failureRedirect: config.loginURL
			}),
			function(req, res) {
				res.redirect(config.homePath);
			}
		);

		app.use(config.secureNamespace, function(req, res, next) {
			if (!req.user) {
				return res.redirect(config.loginURL);
			}
			next();
		});

		app.get(config.logoutURL, function(req, res, next) {
			req.session.destroy();
			req.logout();
			res.redirect(config.loginURL);
		});

		app.use(function(err, req, res, next) {
			cb(err);
		})

		app.use(function(req, res, next) {
			if(req.user) {
				res.proxyHeaders.push(['X-User-Info-Proxy', JSON.stringify(req.user)]);
			}
			cb(null, req, res);
		})

		app(req, res)
	}
}

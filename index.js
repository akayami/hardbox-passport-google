const morgan = require('morgan');
const express = require('express');
const session = require('express-session');
const ejs = require('ejs');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth').OAuth2Strategy;
const HttpForbidden = require('./lib/error/http/forbidden');
const path = require('path');

module.exports = function (config) {

	passport.serializeUser(function (user, done) {
//			console.log('serialize');
		done(null, user);
	});

	passport.deserializeUser(function (obj, done) {
		// done(null, obj);
		if (!config.allowedDomains && config.google.allowedDomains) {
			config.allowedDomains = config.google.allowedDomains;
		}
		if (!config.allowedDomains || config.allowedDomains.includes(obj.domain)) {
			done(null, obj);
		} else {
			done(new HttpForbidden('Domain mismatch: ' + obj.domain + ' not in ' + config.allowedDomains))
		}
	});


	passport.use(new GoogleStrategy({
			clientID: config.google.login.clientID,
			clientSecret: config.google.login.clientSecret,
			callbackURL: config.google.login.fullCallbackURL
		},
		function (accessToken, refreshToken, profile, done) {
			done(null, {
				profile: profile,
				domain: profile._json.domain
			});
		}
	));

	const app = express();

	app.set('views', path.join(__dirname, '/views'));
	app.use(morgan(config.morgan.format, config.morgan.options));
	app.set('view engine', 'ejs');

	if (config.session.storeConf) {
		const sessionStore = require(config.session.storeConf.type)(session);
		config.session.store = new sessionStore(config.session.storeConf.config);
	}

	app.use(session(config.session));

	app.use(config.secureNamespace, passport.initialize());
	app.use(config.secureNamespace, passport.session());

	app.use(config.google.login.callbackURL, passport.initialize());
	app.use(config.google.login.callbackURL, passport.session());

	app.get(config.google.login.loginURL,
		passport.authenticate('google', {
			scope: config.google.scope
		})
	);

	return (req, res, cb) => {

		// app.use(passport.initialize());
		// app.use(passport.session());

		if (config.forwardLogin === false) {
			app.get(config.loginURL, function (req, res, next) {
				req.internalURL = true;
				res.render('login');
			})
		}

		app.get(config.google.login.callbackURL,
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

		app.use(function (err, req, res, next) {
			if (err instanceof HttpForbidden) {
				req.session.destroy();
				req.logout();
			}
			cb(err, req, res);
		});

		app.use(function (req, res, next) {
			if (req.user) {
				res.proxyHeaders.push([config.headerName, JSON.stringify(req.user)]);
			}
			cb(null, req, res);
		});

		app(req, res)
	}
};

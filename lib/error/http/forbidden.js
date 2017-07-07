const HttpError = require('../http.js');

module.exports = class Forbidden extends HttpError {

	constructor(message) {
		super('Forbidden' + (message ? ': ' + message : ''), 403);
	}

}

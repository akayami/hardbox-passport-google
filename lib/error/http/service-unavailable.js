const HttpError = require('../http.js');

module.exports = class ServiceUnavailable extends HttpError {

	constructor(message) {
		super('Service Unavailable' + (message ? ': ' + message : ''), 503);
	}

}

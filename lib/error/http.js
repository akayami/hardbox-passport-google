module.exports = class HttpError extends Error {
	constructor(message, code) {
		super(`[${code}] - ${message}`);
		this.status = code;
	}

	getStatus() {
		return this.status;
	}
}

class ErrorHandler {
  constructor (errorName, message) {
    Error.call(this, message)
    Error.captureStackTrace(this, this.constructor)
    this.name = errorName
    this.message = message
  }
}

export default ErrorHandler

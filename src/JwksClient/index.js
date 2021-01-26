import errorHandler from './errors/index.js'
// Creates a class that fetches a JSON Web Key Set from the jwks_uri and provides methods to return it as a JSON object

class JwksClient {
  constructor ({ jwksUri, audience, issuer, requestHeaders }) {
    this.jwksUri = jwksUri
    this.audience = audience
    this.issuer = issuer
    this.requestHeaders = requestHeaders
  }

  async getKeys () {
    try {
      const response = await fetch(this.jwksUri, {
        headers: this.requestHeaders
      })

      if (response.status < 200 || response.status >= 300) {
        return new errorHandler(
          'JwksError',
          response.body ||
            response.statusMessage ||
            `Http Error ${response.statusCode}`
        )
      }

      const responseJson = await response.json()

      return responseJson
    } catch (error) {
      return {
        error
      }
    }
  }

  async getSigningKeys () {
    try {
      const { keys } = await this.getKeys()

      if (!keys || !keys.length) {
        return new errorHandler(
          'JwksError',
          'The JWKS endpoint did not contain any keys'
        )
      }

      const signingKeys = keys.filter(
        key =>
          key.use === 'sig' &&
          key.kty === 'RSA' &&
          key.kid &&
          ((key.x5c && key.x5c.length) || (key.n && key.e))
      )

      if (!signingKeys.length) {
        return new errorHandler(
          'JwksError',
          'The JWKS endpoint did not contain any signing keys'
        )
      }

      return signingKeys
    } catch (error) {
      return {
        error
      }
    }
  }

  async getSigningKey (kid) {
    try {
      const keys = await this.getSigningKeys()
      const key = keys.find(k => k.kid === kid)

      if (key) {
        return key
      } else {
        return new errorHandler(
          'SigningKeyNotFoundError',
          `Unable to find a signing key that matches '${kid}'`
        )
      }
    } catch (error) {
      return {
        error
      }
    }
  }
}

export { JwksClient }

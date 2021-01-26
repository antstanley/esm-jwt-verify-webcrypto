import validation from './validation/index.js'
import verifyJWT from './verify/index.js'

const validateJWT = async (decodedToken, jwk) => {
  try {
    const valid = await verifyJWT(decodedToken, jwk)
    if (!valid) {
      return { error: 'JsonWebTokenError: invalid signature' }
    }
    return { verified: true }
  } catch (error) {
    return { error }
  }
}

const verify = async (decodedToken, jwk, options) => {
  try {
    if (!options) {
      options = {}
    }

    // clone this object since we are going to mutate it.
    options = Object.assign({}, options)

    const { header, payload, signature } = decodedToken

    const validatedOptions = validation(options, payload, jwk)

    if (validatedOptions.valid) {
      const JWTvalidation = await validateJWT(decodedToken, jwk)
      if (JWTvalidation.verified) {
        if (options.complete === true) {
          return {
            header,
            payload,
            signature
          }
        } else {
          return payload
        }
      } else {
        console.log(JWTvalidation.error)
        return JWTvalidation
      }
    } else {
      const { errors } = validatedOptions
      console.log(`${errors.length} error(s) encountered`)
      errors.forEach(error => {
        console.log(error)
      })
      return { errors }
    }
  } catch (error) {
    return {
      error
    }
  }
}

export default verify

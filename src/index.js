import { JwksClient } from './JwksClient/index.js'
import verifyJWT from './verifyJWT/index.js'
import decodeJWT from './decodeJWT/index.js'
let jwk

const authenticate = async (token, jwksOptions) => {
  try {
    const { jwksUri, audience, issuer } = jwksOptions

    const decodedToken = decodeJWT(token)

    const { header } = decodedToken
    const { kid } = header

    if (!jwk) {
      const client = new JwksClient({ jwksUri })
      jwk = await client.getSigningKey(kid)
    }

    const verifyOptions = {
      audience,
      issuer,
      complete: true
    }

    return verifyJWT(decodedToken, jwk, verifyOptions)
  } catch (error) {
    return {
      error
    }
  }
}

export default authenticate

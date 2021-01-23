import { JwksClient } from './JwksClient/index.js'
import verifyJWT from './verifyJWT/index.js'
import decodeJWT from './decodeJWT/index.js'
let signingKey

const authenticate = async (token, jwksOptions) => {
  try {
    const { jwksUri, audience, issuer } = jwksOptions

    const decodedToken = decodeJWT(token)

    const { header } = decodedToken
    const { kid } = header

    if (!signingKey) {
      const client = new JwksClient({ jwksUri })
      const key = await client.getSigningKey(kid)
      signingKey = key.publicKey || key.rsaPublicKey
    }

    const verifyOptions = {
      audience,
      issuer,
      complete: true
    }

    return verifyJWT(decodedToken, signingKey, verifyOptions)
  } catch (error) {
    return {
      error
    }
  }
}

export default authenticate

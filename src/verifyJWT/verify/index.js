import jwa from './jwa.js'

const jwsVerify = async (decodedToken, secretOrKey) => {
  const { signature, securedInput, header } = decodedToken
  const algorithm = header.alg

  if (!algorithm) {
    const err = new Error('Missing algorithm parameter for jws.verify')
    err.code = 'MISSING_ALGORITHM'
    return err
  }

  const algo = new jwa(algorithm)
  return algo.verify(securedInput, signature, secretOrKey)
}

export default jwsVerify

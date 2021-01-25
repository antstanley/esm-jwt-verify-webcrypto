const MSG_INVALID_ALGORITHM =
  'is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'

async function createHmacVerify (data, signature, jwk, bits) {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'HMAC', hash: `SHA-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify(
    'HMAC',
    key,
    encoder.encode(signature),
    encoder.encode(data)
  )
}

async function createKeyVerify (data, signature, jwk, bits) {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify(
    'RSASSA-PKCS1-v1_5',
    key,
    encoder.encode(signature),
    encoder.encode(data)
  )
}

async function createPSSKeyVerify (data, signature, jwk, bits) {
  const encoder = new TextEncoder()
  const saltLength = Math.ceil((bits - 1) / 8) - bits * 8 - 2
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSA-PSS', hash: `SHA-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify(
    { name: 'RSA-PSS', saltLength },
    key,
    encoder.encode(signature),
    encoder.encode(data)
  )
}

async function createECDSAVerify (data, signature, jwk, bits) {
  const encoder = new TextEncoder()
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'ECDSA', namedCurve: `P-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify(
    { name: 'ECDSA', hash: `SHA-${bits}` },
    key,
    encoder.encode(signature),
    encoder.encode(data)
  )
}

function createNoneVerifier (thing, signature) {
  return signature === ''
}

class jwa {
  constructor (algorithm) {
    const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i)
    if (!match) throw new Error(MSG_INVALID_ALGORITHM, algorithm)
    this.algo = (match[1] || match[3]).toLowerCase()
    this.bits = match[2]
  }

  verify (thing, signature, jwk) {
    switch (this.algo) {
      case 'hs':
        return createHmacVerify(thing, signature, jwk, this.bits)
        break
      case 'rs':
        return createKeyVerify(thing, signature, jwk, this.bits)
        break
      case 'ps':
        return createPSSKeyVerify(thing, signature, jwk, this.bits)
        break
      case 'es':
        return createECDSAVerify(thing, signature, jwk, this.bits)
        break
      case 'none':
        return createNoneVerifier(thing, signature)
        break
      default:
        return { error: 'no valid algorithm declared' }
    }
  }
}

export default jwa

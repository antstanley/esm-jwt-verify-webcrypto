const MSG_INVALID_ALGORITHM =
  'is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'

function byteStringToUint8Array (byteString) {
  const ui = new Uint8Array(byteString.length)
  for (let i = 0; i < byteString.length; ++i) {
    ui[i] = byteString.charCodeAt(i)
  }
  return ui
}

async function createHmacVerify ({ data, signature, jwk, bits }) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'HMAC', hash: `SHA-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify('HMAC', key, signature, data)
}

async function createKeyVerify ({ data, signature, jwk, bits }) {
  const key = await crypto.subtle.importKey(
    'jwk',
    jwk,
    { name: 'RSASSA-PKCS1-v1_5', hash: `SHA-${bits}` },
    false,
    ['verify']
  )

  return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, signature, data)
}

async function createPSSKeyVerify ({ data, signature, jwk, bits }) {
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
    signature,
    data
  )
}

async function createECDSAVerify ({ data, signature, jwk, bits }) {
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
    signature,
    data
  )
}

function createNoneVerifier ({ data, signature, jwk, bits }) {
  return signature === ''
}

class jwa {
  constructor (algorithm) {
    const match = algorithm.match(/^(RS|PS|ES|HS)(256|384|512)$|^(none)$/i)
    if (!match) throw new Error(MSG_INVALID_ALGORITHM, algorithm)
    this.algo = (match[1] || match[3]).toLowerCase()
    this.bits = match[2]
  }

  verify (data, signature, jwk) {
    const encoder = new TextEncoder()
    const opts = {
      data: encoder.encode(data),
      signature: byteStringToUint8Array(
        atob(signature.replace(/_/g, '/').replace(/-/g, '+'))
      ),
      jwk,
      bits: this.bits
    }

    switch (this.algo) {
      case 'hs':
        return createHmacVerify(opts)
        break
      case 'rs':
        return createKeyVerify(opts)
        break
      case 'ps':
        return createPSSKeyVerify(opts)
        break
      case 'es':
        return createECDSAVerify(opts)
        break
      case 'none':
        return createNoneVerifier(opts)
        break
      default:
        return { error: 'no valid algorithm declared' }
    }
  }
}

export default jwa

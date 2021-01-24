// import formatEcdsa from 'ecdsa-sig-formatter'

const MSG_INVALID_ALGORITHM =
  'is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'
// const MSG_INVALID_SECRET = 'secret must be a string or Uint8Array'
// let MSG_INVALID_VERIFIER_KEY = 'key must be a string or a Uint8Array'

// const supportsKeyObjects = typeof crypto.createPublicKey === 'function'
// if (supportsKeyObjects) {
//   MSG_INVALID_VERIFIER_KEY += ' or a KeyObject'
// }

// function checkIsPublicKey (key) {
//   if (key instanceof Uint8Array) {
//     return key
//   }
//
//   if (typeof key === 'string') {
//     return key
//   }
//
//   // if (!supportsKeyObjects) {
//   //   throw typeError(MSG_INVALID_VERIFIER_KEY)
//   // }
//
//   if (typeof key !== 'object') {
//     throw typeError(MSG_INVALID_VERIFIER_KEY)
//   }
//
//   if (typeof key.type !== 'string') {
//     throw typeError(MSG_INVALID_VERIFIER_KEY)
//   }
//
//   if (typeof key.asymmetricKeyType !== 'string') {
//     throw typeError(MSG_INVALID_VERIFIER_KEY)
//   }
//
//   if (typeof key.export !== 'function') {
//     throw typeError(MSG_INVALID_VERIFIER_KEY)
//   }
//
//   return key
// }

// function fromBase64 (base64) {
//   return base64
//     .replace(/=/g, '')
//     .replace(/\+/g, '-')
//     .replace(/\//g, '_')
// }
//
// function toBase64 (base64url) {
//   base64url = base64url.toString()
//
//   var padding = 4 - (base64url.length % 4)
//   if (padding !== 4) {
//     for (var i = 0; i < padding; ++i) {
//       base64url += '='
//     }
//   }
//
//   return base64url.replace(/\-/g, '+').replace(/_/g, '/')
// }

// function typeError (template, algorithm) {
//   const errMsg = algorithm ? `"${algorithm}" ${template}` : template
//   return new TypeError(errMsg)
// }
//
// function bufferOrString (obj) {
//   return obj instanceof Uint8Array || typeof obj === 'string'
// }
//
// function normalizeInput (thing) {
//   if (!bufferOrString(thing)) thing = JSON.stringify(thing)
//   return thing
// }
//
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

// function createHmacVerifier (thing, signature, secret, bits) {
//   const encoder = new TextEncoder()
//   const computedSig = createHmacSigner(bits)(thing, secret)
//   const computedSigBuffer = encoder.encode(computedSig)
//   const sigBuffer = encoder.encode(signature)
//   return Uint8ArrayEqual(computedSigBuffer, sigBuffer)
// }

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

// function createKeyVerifier (thing, signature, publicKey, bits) {
//   const key = checkIsPublicKey(publicKey)
//   thing = normalizeInput(thing)
//   signature = btoa(signature)
//   const verifier = crypto.createVerify('RSA-SHA' + bits)
//   verifier.update(thing)
//   return verifier.verify(key, signature, 'base64')
// }

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

// function createPSSKeyVerifier (thing, signature, publicKey, bits) {
//   if (!bufferOrString(publicKey)) throw typeError(MSG_INVALID_VERIFIER_KEY)
//   thing = normalizeInput(thing)
//   signature = btoa(signature)
//   const verifier = crypto.createVerify('RSA-SHA' + bits)
//   verifier.update(thing)
//   return verifier.verify(
//     { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
//     signature,
//     'base64'
//   )
// }

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

// function createECDSAVerifer (thing, signature, publicKey, bits) {
//   signature = formatEcdsa.joseToDer(signature, 'ES' + bits).toString('base64')
//   var result = createKeyVerifier(thing, signature, publicKey, bits)
//   return result
// }

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

  verify (thing, signature, publicKeyorSecret) {
    switch (this.algo) {
      case 'hs':
        return createHmacVerify(thing, signature, publicKeyorSecret, this.bits)
        break
      case 'rs':
        return createKeyVerify(thing, signature, publicKeyorSecret, this.bits)
        break
      case 'ps':
        return createPSSKeyVerify(
          thing,
          signature,
          publicKeyorSecret,
          this.bits
        )
        break
      case 'es':
        return createECDSAVerify(thing, signature, publicKeyorSecret, this.bits)
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

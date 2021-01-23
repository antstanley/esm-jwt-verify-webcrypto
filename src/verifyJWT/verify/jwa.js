import crypto from 'crypto'
import formatEcdsa from 'ecdsa-sig-formatter'

const MSG_INVALID_ALGORITHM =
  'is not a valid algorithm.\n  Supported algorithms are:\n  "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512" and "none".'
const MSG_INVALID_SECRET = 'secret must be a string or buffer'
let MSG_INVALID_VERIFIER_KEY = 'key must be a string or a buffer'

const supportsKeyObjects = typeof crypto.createPublicKey === 'function'
if (supportsKeyObjects) {
  MSG_INVALID_VERIFIER_KEY += ' or a KeyObject'
}

function checkIsPublicKey (key) {
  if (Buffer.isBuffer(key)) {
    return key
  }

  if (typeof key === 'string') {
    return key
  }

  if (!supportsKeyObjects) {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key !== 'object') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.type !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.asymmetricKeyType !== 'string') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  if (typeof key.export !== 'function') {
    throw typeError(MSG_INVALID_VERIFIER_KEY)
  }

  return key
}

function fromBase64 (base64) {
  return base64
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
}

function toBase64 (base64url) {
  base64url = base64url.toString()

  var padding = 4 - (base64url.length % 4)
  if (padding !== 4) {
    for (var i = 0; i < padding; ++i) {
      base64url += '='
    }
  }

  return base64url.replace(/\-/g, '+').replace(/_/g, '/')
}

function typeError (template, algorithm) {
  const errMsg = algorithm ? `"${algorithm}" ${template}` : template
  return new TypeError(errMsg)
}

function bufferOrString (obj) {
  return Buffer.isBuffer(obj) || typeof obj === 'string'
}

function normalizeInput (thing) {
  if (!bufferOrString(thing)) thing = JSON.stringify(thing)
  return thing
}

function createHmacSigner (bits) {
  return function sign (thing, secret) {
    if (!bufferOrString(secret)) throw typeError(MSG_INVALID_SECRET)
    thing = normalizeInput(thing)
    const hmac = crypto.createHmac('sha' + bits, secret)
    const sig = (hmac.update(thing), hmac.digest('base64'))
    return fromBase64(sig)
  }
}

function createHmacVerifier (thing, signature, secret, bits) {
  const computedSig = createHmacSigner(bits)(thing, secret)
  const computedSigBuffer = Buffer.from(computedSig)
  const sigBuffer = Buffer.from(signature)
  return sigBuffer.equals(computedSigBuffer)
}

function createKeyVerifier (thing, signature, publicKey, bits) {
  const key = checkIsPublicKey(publicKey)
  thing = normalizeInput(thing)
  signature = toBase64(signature)
  const verifier = crypto.createVerify('RSA-SHA' + bits)
  verifier.update(thing)
  return verifier.verify(key, signature, 'base64')
}

function createPSSKeyVerifier (thing, signature, publicKey, bits) {
  if (!bufferOrString(publicKey)) throw typeError(MSG_INVALID_VERIFIER_KEY)
  thing = normalizeInput(thing)
  signature = toBase64(signature)
  const verifier = crypto.createVerify('RSA-SHA' + bits)
  verifier.update(thing)
  return verifier.verify(
    { key: publicKey, padding: crypto.constants.RSA_PKCS1_PSS_PADDING },
    signature,
    'base64'
  )
}

function createECDSAVerifer (thing, signature, publicKey, bits) {
  signature = formatEcdsa.joseToDer(signature, 'ES' + bits).toString('base64')
  var result = createKeyVerifier(thing, signature, publicKey, bits)
  return result
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

  verify (thing, signature, publicKeyorSecret) {
    switch (this.algo) {
      case 'hs':
        return createHmacVerifier(
          thing,
          signature,
          publicKeyorSecret,
          this.bits
        )
        break
      case 'rs':
        return createKeyVerifier(thing, signature, publicKeyorSecret, this.bits)
        break
      case 'ps':
        return createPSSKeyVerifier(
          thing,
          signature,
          publicKeyorSecret,
          this.bits
        )
        break
      case 'es':
        return createECDSAVerifer(
          thing,
          signature,
          publicKeyorSecret,
          this.bits
        )
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

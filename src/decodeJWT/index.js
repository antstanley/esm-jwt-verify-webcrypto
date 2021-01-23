const JWS_REGEX = /^[a-zA-Z0-9\-_]+?\.[a-zA-Z0-9\-_]+?\.([a-zA-Z0-9\-_]+)?$/

function toString (obj) {
  if (typeof obj === 'string') return obj
  if (typeof obj === 'number' || Buffer.isBuffer(obj)) return obj.toString()
  return JSON.stringify(obj)
}

function isObject (thing) {
  return Object.prototype.toString.call(thing) === '[object Object]'
}

function safeJsonParse (thing) {
  if (isObject(thing)) return thing
  try {
    return JSON.parse(thing)
  } catch (e) {
    return undefined
  }
}

function securedInputFromJWS (jwsSig) {
  return jwsSig.split('.', 2).join('.')
}

function headerFromJWS (jwsSig) {
  const encodedHeader = jwsSig.split('.', 1)[0]
  return safeJsonParse(Buffer.from(encodedHeader, 'base64').toString('binary'))
}

function signatureFromJWS (jwsSig) {
  return jwsSig.split('.')[2]
}

function payloadFromJWS (jwsSig, encoding) {
  encoding = encoding || 'utf8'
  const payload = jwsSig.split('.')[1]
  return Buffer.from(payload, 'base64').toString(encoding)
}

function isValidJws (string) {
  return JWS_REGEX.test(string) && !!headerFromJWS(string)
}

const jwsDecode = (jwsSig, opts) => {
  try {
    opts = opts || {}
    jwsSig = toString(jwsSig)

    if (!isValidJws(jwsSig)) {
      return {
        error: `Unable to decode token. ${jwsSig} is invalid`
      }
    }

    const header = headerFromJWS(jwsSig)
    if (!header) {
      return {
        error: `Unable to decode token. No header present`
      }
    }
    let payload = payloadFromJWS(jwsSig)
    if (header.typ === 'JWT' || opts.json) {
      payload = JSON.parse(payload, opts.encoding)
    }
    const signature = signatureFromJWS(jwsSig)
    const securedInput = securedInputFromJWS(jwsSig)

    return {
      header,
      payload,
      signature,
      securedInput
    }
  } catch (error) {
    return {
      error: `Unable to decode token with error:\n ${error}`
    }
  }
}

export default jwsDecode

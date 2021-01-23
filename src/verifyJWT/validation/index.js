const PUB_KEY_ALGS = [
  'RS256',
  'RS384',
  'RS512',
  'ES256',
  'ES384',
  'ES512',
  'PS256',
  'PS384',
  'PS512'
]
const RSA_KEY_ALGS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512']
const HS_ALGS = ['HS256', 'HS384', 'HS512']

const timespan = (time, iat) => {
  const timestamp = iat || Math.floor(Date.now() / 1000)

  if (typeof time === 'string') {
    const timeDate = new Date(time)
    const milliseconds = timeDate.getMilliseconds()
    if (typeof milliseconds === 'undefined') {
      return
    }
    return Math.floor(timestamp + milliseconds / 1000)
  } else if (typeof time === 'number') {
    return timestamp + time
  }
}

const validation = (options, payload, secretOrPublicKey) => {
  let errorArray = []

  if (!options.algorithms) {
    options.algorithms = ['none']
  }

  if (!options.algorithms) {
    options.algorithms =
      ~secretOrPublicKey.toString().indexOf('BEGIN CERTIFICATE') ||
      ~secretOrPublicKey.toString().indexOf('BEGIN PUBLIC KEY')
        ? PUB_KEY_ALGS
        : ~secretOrPublicKey.toString().indexOf('BEGIN RSA PUBLIC KEY')
          ? RSA_KEY_ALGS
          : HS_ALGS
  }

  if (options.clockTimestamp && typeof options.clockTimestamp !== 'number') {
    errorArray.push('JsonWebTokenError:clockTimestamp must be a number')
  }
  const clockTimestamp = options.clockTimestamp || Math.floor(Date.now() / 1000)

  if (
    options.nonce !== undefined &&
    (typeof options.nonce !== 'string' || options.nonce.trim() === '')
  ) {
    errorArray.push('JsonWebTokenError: nonce must be a non-empty string')
  }

  if (!secretOrPublicKey) {
    errorArray.push('JsonWebTokenError: secret or public key must be provided')
  }

  if (typeof payload.nbf !== 'undefined' && !options.ignoreNotBefore) {
    if (typeof payload.nbf !== 'number') {
      errorArray.push('JsonWebTokenError: invalid nbf value')
    }
    if (payload.nbf > clockTimestamp + (options.clockTolerance || 0)) {
      errorArray.push(
        `NotBeforeError: jwt not active ${new Date(payload.nbf * 1000)}`
      )
    }
  }

  if (typeof payload.exp !== 'undefined' && !options.ignoreExpiration) {
    if (typeof payload.exp !== 'number') {
      errorArray.push('JsonWebTokenError: invalid exp value')
    }
    if (clockTimestamp >= payload.exp + (options.clockTolerance || 0)) {
      errorArray.push(
        `TokenExpiredError: jwt expired ${new Date(payload.exp * 1000)}`
      )
    }
  }

  if (options.audience) {
    const audiences = Array.isArray(options.audience)
      ? options.audience
      : [options.audience]
    const target = Array.isArray(payload.aud) ? payload.aud : [payload.aud]

    const match = target.some(function (targetAudience) {
      return audiences.some(function (audience) {
        return audience instanceof RegExp
          ? audience.test(targetAudience)
          : audience === targetAudience
      })
    })

    if (!match) {
      errorArray.push(
        `JsonWebTokenError: jwt audience invalid. expected: ${audiences.join(
          ' or '
        )}`
      )
    }
  }

  if (options.issuer) {
    const invalid_issuer =
      (typeof options.issuer === 'string' && payload.iss !== options.issuer) ||
      (Array.isArray(options.issuer) &&
        options.issuer.indexOf(payload.iss) === -1)

    if (invalid_issuer) {
      errorArray.push(
        `JsonWebTokenError: jwt issuer invalid. expected: ${options.issuer}`
      )
    }
  }

  if (options.subject) {
    if (payload.sub !== options.subject) {
      errorArray.push(
        `JsonWebTokenError: jwt subject invalid. expected: ${options.subject}`
      )
    }
  }

  if (options.jwtid) {
    if (payload.jti !== options.jwtid) {
      errorArray.push(
        `JsonWebTokenError: jwt jwtid invalid. expected: ${options.jwtid}`
      )
    }
  }

  if (options.nonce) {
    if (payload.nonce !== options.nonce) {
      errorArray.push(
        `JsonWebTokenError: jwt nonce invalid. expected: ${options.nonce}`
      )
    }
  }

  if (options.maxAge) {
    if (typeof payload.iat !== 'number') {
      errorArray.push(
        'JsonWebTokenError: iat required when maxAge is specified'
      )
    }

    const maxAgeTimestamp = timespan(options.maxAge, payload.iat)
    if (typeof maxAgeTimestamp === 'undefined') {
      errorArray.push(
        'JsonWebTokenError: "maxAge" should be a number of seconds or string representing a timespan eg: "1d", "20h", 60'
      )
    }
    if (clockTimestamp >= maxAgeTimestamp + (options.clockTolerance || 0)) {
      errorArray.push(
        `TokenExpiredError: maxAge exceeded ${new Date(maxAgeTimestamp * 1000)}`
      )
    }
  }

  if (errorArray.length === 0) {
    options.valid = true
    return options
  } else {
    return { errors: errorArray }
  }
}

export default validation

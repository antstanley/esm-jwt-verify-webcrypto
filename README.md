# @esmodule/jwt-verify-webcrypto

ES module to verify JWT signatures using the WebCrypto API.

## Usage

```js
import authenticate from '@esmodule/jwt-verify-webcrypto'

const validateToken = async (token) => {
    const options = {
        jwksUri: 'https://<openid-tenant-url>/.well-known/jwks.json',
        requestHeaders: {}
    }

    return authenticate(token, options)
}

export default validateToken

```

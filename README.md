# @esmodule/jwt-verify

ES module to verify JWT signatures.

## Usage

```js
import authenticate from '@esmodule/jwt-verify'

const validateToken = async (token) => {
    const options = {
        jwksUri: 'https://<openid-tenant-url>/.well-known/jwks.json',
        requestHeaders: {}
    }

    return authenticate(token, options)
}

export default validateToken

```

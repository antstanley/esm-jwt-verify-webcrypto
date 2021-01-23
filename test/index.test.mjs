import authenticate from '../src'

const testToken =
  'eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsImtpZCI6IlJqWTVORFpFTmtJNU9EazVNalEwUTBZelEwUkVNemRGTnpsRE1VWXlSREJDUmpSQ1FVVkdOZyJ9.eyJpc3MiOiJodHRwczovL3NlbnpvLmV1LmF1dGgwLmNvbS8iLCJzdWIiOiI0MzNFWTY4OXVqck44bzZTVlhOb3dsUE92SHRhNjJwSkBjbGllbnRzIiwiYXVkIjoiaHR0cHM6Ly9zZW56by5ldS5hdXRoMC5jb20vYXBpL3YyLyIsImlhdCI6MTU1MTIyNDEwNSwiZXhwIjoxNTUxMzEwNTA1LCJhenAiOiI0MzNFWTY4OXVqck44bzZTVlhOb3dsUE92SHRhNjJwSiIsImd0eSI6ImNsaWVudC1jcmVkZW50aWFscyJ9.AIcSKI4nQzT39wpr2ETaOzKxS2Qc9JOeTMxzwayrkN6JYtAGPMxntJswy2arpFlc_EO_lFQxXShMVoxckfgWYoldfDW9oWk4iE1N6GL8HbEhlh2sPhKu9vtcjqYY77gaiI40Sota74utoeaWyiXYvipdAW4VkiNVvdkTAEp_TuQZbeobOHdl7LroySqtBesBMc18NXX2LfMWrYod3da0MsnFQrywTHxjCr80Mi8k7grh1L4EL_ie8y1-QMMHa3HEi_An2EabH7Jn4me8VEqhE7bvsUHmNhxpv-5Q1ski7MonWMzA4hqInLIlG_1AoEioDyD7eZNVJmIM9RdFUqhfLw'

const jwksOpts = {
  jwksUri: 'https://senzo.eu.auth0.com/.well-known/jwks.json',
  audience: 'https://senzo.eu.auth0.com/api/v2/',
  issuer: 'https://senzo.eu.auth0.com/'
}

const getAuthToken = async testToken => {
  console.time('Entire process')
  const authToken = await authenticate(testToken, jwksOpts)
  console.timeEnd('Entire process')
  console.log(authToken)
  return authToken
}

const response = getAuthToken(testToken)

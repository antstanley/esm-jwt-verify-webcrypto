import { JwksClient } from '../../src/JwksClient'

const fetchKey = async () => {
  console.time()
  const client = new JwksClient({
    jwksUri: '',
    requestHeaders: {} // Optional
  })

  const kid = ''
  const key = await client.getSigningKey(kid)
  const signingKey = key.publicKey || key.rsaPublicKey
  console.timeEnd()
  console.log(`signingKey: ${signingKey}`)
  // Now I can use this to configure my Express or Hapi middleware
}

const newKey = fetchKey()

// console.log(newKey)

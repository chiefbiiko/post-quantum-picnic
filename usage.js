const pqp = require('./index')

// const params = 1
// const keys = pqp.keygen(params)
// console.log('params:', params, 'keys:', keys)

const secretkey = {
  params: 1,
  data: Buffer.from('acab'),
  publickey: {
    params: 1,
    plaintext: Buffer.from('deadbeefdeadbeefdeadbeefdeadbeef'),
    ciphertext: Buffer.from('deadbeefdeadbeefdeadbeefdeadbeef')
  }
}
const signature = pqp.sign(secretkey, Buffer.from('fraud'))
console.log('signature:', signature)

const pqp = require('./index')

const secretkey = {
  params: pqp.PARAMS.Picnic_L1_FS,
  data: Buffer.from('acab'),
  publickey: {
    params: pqp.PARAMS.Picnic_L1_FS,
    plaintext: Buffer.from('deadbeefdeadbeefdeadbeefdeadbeef'),
    ciphertext: Buffer.from('deadbeefdeadbeefdeadbeefdeadbeef')
  }
}
const signature = pqp.sign(secretkey, Buffer.from('fraud'))
console.log('signature:', signature, 'length:', signature.length)

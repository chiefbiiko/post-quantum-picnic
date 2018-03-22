const tape = require('tape')
const pqp = require('./index')
const isNumber = require('util').isNumber

function isPojo (x) {
  return x && Object.getPrototypeOf(x) === Object.prototype
}

tape('pqp.PARAMS', function (t) {
  const expected = {
    PARAMETER_SET_INVALID: 0,
    Picnic_L1_FS: 1,
    Picnic_L1_UR: 2,
    Picnic_L3_FS: 3,
    Picnic_L3_UR: 4,
    Picnic_L5_FS: 5,
    Picnic_L5_UR: 6,
    PARAMETER_SET_MAX_INDEX: 7
  }
  t.ok(pqp.PARAMS,  'got an export named "PARAMS"')
  t.same(pqp.PARAMS, expected, 'met expectation')
  t.end()
})

tape('pqp.getParamName', function (t) {
  const params = pqp.PARAMS.Picnic_L1_FS
  const name = pqp.getParamName(params)
  t.is(name, 'Picnic_L1_FS', 'got the right name')
  t.end()
})

tape('pqp.keygen', function (t) {
  const keys = pqp.keygen(pqp.PARAMS.Picnic_L1_FS)
  t.ok(isPojo(keys),
    'keys is a pojo')
  t.ok(isPojo(keys.publickey),
    'keys.publickey is a pojo')
  t.ok(isPojo(keys.secretkey),
    'keys.secretkey is a pojo')
  t.ok(isNumber(keys.publickey.params),
    'keys.publickey.params is a number')
  t.ok(Buffer.isBuffer(keys.publickey.plaintext),
    'keys.publickey.plaintext is a buffer')
  t.ok(Buffer.isBuffer(keys.publickey.ciphertext),
    'keys.publickey.ciphertext is a buffer')
  t.ok(isNumber(keys.secretkey.params),
    'keys.secretkey.params is a number')
  t.ok(Buffer.isBuffer(keys.secretkey.data),
    'keys.secretkey.data is a buffer')
  t.ok(isPojo(keys.secretkey.publickey),
    'keys.secretkey.publickey is a pojo')
  t.ok(isNumber(keys.secretkey.publickey.params),
    'keys.secretkey.publickey.params is a number')
  t.ok(Buffer.isBuffer(keys.secretkey.publickey.plaintext),
    'keys.secretkey.publickey.plaintext is a buffer')
  t.ok(Buffer.isBuffer(keys.secretkey.publickey.ciphertext),
    'keys.secretkey.publickey.ciphertext is a buffer')
  t.end()
})

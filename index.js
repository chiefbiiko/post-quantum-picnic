const napi_exports = require('bindings')('pqp')

// TODO:
//   + type check wrappers for all napi_functions
//   + move PARAMS into C

const PARAMS = Object.freeze({
  PARAMETER_SET_INVALID: 0,
  Picnic_L1_FS: 1,
  Picnic_L1_UR: 2,
  Picnic_L3_FS: 3,
  Picnic_L3_UR: 4,
  Picnic_L5_FS: 5,
  Picnic_L5_UR: 6,
  PARAMETER_SET_MAX_INDEX: 7
})

module.exports = {
  PARAMS: PARAMS,
  getParamName: napi_exports.getParamName,
  signatureSize: napi_exports.signatureSize,
  keygen: napi_exports.keygen,
  sign: napi_exports.sign,
  verify: napi_exports.verify
}

#include <node_api.h>
#include "picnic.h"

// TODO:
//   + make castToSecretKey and castToPublicKey standalone functions!!!!!!!!!!!

#define SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

#define THROW_MAYBE(env, status) \
  if (status != 0) napi_throw_error(env, NULL, "native call failed");

napi_value getParamName (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status);

  int params;
  status = napi_get_value_int32(env, argv[0], &params);
  THROW_MAYBE(env, status);

  const char* name = picnic_get_param_name(params);

  napi_value paramname;
  status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &paramname);
  THROW_MAYBE(env, status);

  return paramname;
}

napi_value keygen (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status);

  int params;
  status = napi_get_value_int32(env, argv[0], &params);
  THROW_MAYBE(env, status);

  picnic_publickey_t pk;
  picnic_privatekey_t sk;
  int code = picnic_keygen(params, &pk, &sk);
  THROW_MAYBE(env, code);

  napi_value publickey;
  status = napi_create_object(env, &publickey);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, publickey, "params", argv[0]);
  THROW_MAYBE(env, status);

  napi_value plaintext;
  uint8_t plaintext_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) pk.plaintext, (void**) &plaintext_buffer, &plaintext);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, publickey, "plaintext", plaintext);
  THROW_MAYBE(env, status);

  napi_value ciphertext;
  uint8_t ciphertext_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) pk.ciphertext, (void**) &ciphertext_buffer, &ciphertext);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, publickey, "ciphertext", ciphertext);
  THROW_MAYBE(env, status);

  napi_value secretkey;
  status = napi_create_object(env, &secretkey);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, secretkey, "params", argv[0]);
  THROW_MAYBE(env, status);

  napi_value data;
  uint8_t data_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) sk.data, (void**) &data_buffer, &data);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, secretkey, "data", data);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, secretkey, "publickey", publickey);
  THROW_MAYBE(env, status);

  napi_value keys;
  status = napi_create_object(env, &keys);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, keys, "publickey", publickey);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, keys, "secretkey", secretkey);
  THROW_MAYBE(env, status);

  return keys;
}

napi_value sign_wrapper (napi_env env, napi_callback_info info) {
  napi_status status;
  // secretkey:Object, message:Buffer
  size_t argc = 2; // ...deriving: msg_len, sig, sig_len
  napi_value argv[2];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status);

  // getting napi_value argv[0] as picnic_privatekey_t sk
  napi_value secretkey_params;
  status = napi_get_named_property(env, argv[0], "params", &secretkey_params);
  THROW_MAYBE(env, status);
  int sk_params;
  status = napi_get_value_int32(env, secretkey_params, &sk_params);
  THROW_MAYBE(env, status);

  napi_value secretkey_data;
  status = napi_get_named_property(env, argv[0], "data", &secretkey_data);
  THROW_MAYBE(env, status);
  uint8_t sk_data[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_data_len;
  status = napi_get_buffer_info(env, secretkey_data, (void**) &sk_data, &sk_data_len);
  THROW_MAYBE(env, status);

  napi_value secretkey_publickey;
  status = napi_get_named_property(env, argv[0], "publickey", &secretkey_publickey);
  THROW_MAYBE(env, status);

  napi_value secretkey_publickey_params;
  status = napi_get_named_property(env, secretkey_publickey, "params",
    &secretkey_publickey_params);
  THROW_MAYBE(env, status);
  int sk_pk_params;
  status = napi_get_value_int32(env, secretkey_publickey_params,
    &sk_pk_params);
  THROW_MAYBE(env, status);

  napi_value secretkey_publickey_plaintext;
  status = napi_get_named_property(env, secretkey_publickey, "plaintext",
    &secretkey_publickey_plaintext);
  THROW_MAYBE(env, status);
  uint8_t sk_pk_plaintext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_pk_plaintext_len;
  status = napi_get_buffer_info(env, secretkey_publickey_plaintext,
    (void**) &sk_pk_plaintext, &sk_pk_plaintext_len);
  THROW_MAYBE(env, status);

  napi_value secretkey_publickey_ciphertext;
  status = napi_get_named_property(env, secretkey_publickey, "ciphertext",
    &secretkey_publickey_ciphertext);
  THROW_MAYBE(env, status);
  uint8_t sk_pk_ciphertext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_pk_ciphertext_len;
  status = napi_get_buffer_info(env, secretkey_publickey_ciphertext,
    (void**) &sk_pk_ciphertext, &sk_pk_ciphertext_len);
  THROW_MAYBE(env, status);

  picnic_publickey_t sk_pk = {
    .params = sk_pk_params,
    .plaintext = *sk_pk_plaintext,
    .ciphertext = *sk_pk_ciphertext
  };

  picnic_privatekey_t sk = {
    .params = sk_params,
    .data = *sk_data,
    .pk = sk_pk
  };

  // getting napi_value argv[1] as uint8_t msg[]
  size_t msg_len;
  uint8_t msg[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  status = napi_get_buffer_info(env, argv[1], (void**) &msg, &msg_len);
  THROW_MAYBE(env, status);

  size_t req_sig_len = picnic_signature_size(sk.params);
  uint8_t* sig = malloc(req_sig_len * sizeof(uint8_t));
  size_t sig_len;

  // FAILS!!! TODO: FIX & get the signature!!!
  // int code = picnic_sign(&sk, msg, msg_len, sig, &sig_len);
  // THROW_MAYBE(env, code);

  // TODO: pass the signature back to node!!!!


  free(sig);
  return secretkey_publickey;
}

napi_value init (napi_env env, napi_value exports) {
  napi_status status;

  napi_value keygen_export;
  status = napi_create_function(env, NULL, 0, keygen, NULL, &keygen_export);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, exports, "keygen", keygen_export);
  THROW_MAYBE(env, status);

  napi_value getParamName_export;
  status = napi_create_function(env, NULL, 0, getParamName, NULL,
    &getParamName_export);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, exports, "getParamName",
    getParamName_export);
  THROW_MAYBE(env, status);

  napi_value sign_wrapper_export;
  status = napi_create_function(env, NULL, 0, sign_wrapper, NULL,
    &sign_wrapper_export);
  THROW_MAYBE(env, status);

  status = napi_set_named_property(env, exports, "sign",
    sign_wrapper_export);
  THROW_MAYBE(env, status);

  // public picnic API surface...
  // ...

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);

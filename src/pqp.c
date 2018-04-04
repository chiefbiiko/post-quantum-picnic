#include <stdio.h>
#include <string.h>
#include <node_api.h>
#include "picnic.h"

#define THROW_MAYBE(env, status, msg) \
  if (status != 0) napi_throw_error(env, NULL, msg);

// args:: params:Number
napi_value getParamName (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status, "napi_get_cb_info failed");

  int params;
  status = napi_get_value_int32(env, argv[0], &params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  const char* name = picnic_get_param_name((picnic_params_t) params);

  napi_value paramname;
  status = napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &paramname);
  THROW_MAYBE(env, status, "napi_create_string_utf8 failed");

  return paramname;
}

// args:: params:Number
napi_value signatureSize (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status, "napi_get_cb_info failed");

  int params;
  status = napi_get_value_int32(env, argv[0], &params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  size_t sig_size = picnic_signature_size((picnic_params_t) params);

  napi_value signature_size;
  status = napi_create_int32(env, (int32_t) sig_size, &signature_size);

  return signature_size;
}

// args:: params:Number
napi_value keygen (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 1;
  napi_value argv[1];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status, "napi_get_cb_info failed");

  int params;
  status = napi_get_value_int32(env, argv[0], &params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  picnic_publickey_t pk;
  picnic_privatekey_t sk;

  int code = picnic_keygen((picnic_params_t) params, &pk, &sk);
  THROW_MAYBE(env, code, "picnic_keygen failed");

  napi_value publickey;
  status = napi_create_object(env, &publickey);
  THROW_MAYBE(env, status, "napi_create_object failed");

  status = napi_set_named_property(env, publickey, "params", argv[0]);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value plaintext;
  uint8_t plaintext_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];

  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) pk.plaintext, (void**) &plaintext_buffer, &plaintext);
  THROW_MAYBE(env, status, "napi_create_buffer_copy failed");

  status = napi_set_named_property(env, publickey, "plaintext", plaintext);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value ciphertext;
  uint8_t ciphertext_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];

  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) pk.ciphertext, (void**) &ciphertext_buffer, &ciphertext);
  THROW_MAYBE(env, status, "napi_create_buffer_copy failed");

  status = napi_set_named_property(env, publickey, "ciphertext", ciphertext);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value privatekey;
  status = napi_create_object(env, &privatekey);
  THROW_MAYBE(env, status, "napi_create_object failed");

  status = napi_set_named_property(env, privatekey, "params", argv[0]);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value data;
  uint8_t data_buffer[PICNIC_MAX_LOWMC_BLOCK_SIZE];

  status = napi_create_buffer_copy(env, PICNIC_MAX_LOWMC_BLOCK_SIZE,
    (void*) sk.data, (void**) &data_buffer, &data);
  THROW_MAYBE(env, status, "napi_create_buffer_copy failed");

  status = napi_set_named_property(env, privatekey, "data", data);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  status = napi_set_named_property(env, privatekey, "publickey", publickey);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value keys;
  status = napi_create_object(env, &keys);
  THROW_MAYBE(env, status, "napi_create_object failed");

  status = napi_set_named_property(env, keys, "publickey", publickey);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  status = napi_set_named_property(env, keys, "privatekey", privatekey);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  return keys;
}

// args:: privatekey:Object, message:Buffer
napi_value sign_wrapper (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 2;
  napi_value argv[2];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status, "napi_get_cb_info failed");

  // getting napi_value argv[0] as picnic_privatekey_t sk
  napi_value privatekey_params;
  status = napi_get_named_property(env, argv[0], "params", &privatekey_params);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int sk_params;
  status = napi_get_value_int32(env, privatekey_params, &sk_params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  napi_value privatekey_data;
  status = napi_get_named_property(env, argv[0], "data", &privatekey_data);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  uint8_t sk_data[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_data_len;

  status = napi_get_buffer_info(env, privatekey_data, (void**) &sk_data,
    &sk_data_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  napi_value privatekey_publickey;
  status = napi_get_named_property(env, argv[0], "publickey",
    &privatekey_publickey);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  napi_value privatekey_publickey_params;
  status = napi_get_named_property(env, privatekey_publickey, "params",
    &privatekey_publickey_params);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int sk_pk_params;
  status = napi_get_value_int32(env, privatekey_publickey_params,
    &sk_pk_params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  napi_value privatekey_publickey_plaintext;
  status = napi_get_named_property(env, privatekey_publickey, "plaintext",
    &privatekey_publickey_plaintext);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  uint8_t sk_pk_plaintext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_pk_plaintext_len;

  status = napi_get_buffer_info(env, privatekey_publickey_plaintext,
    (void**) &sk_pk_plaintext, &sk_pk_plaintext_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  napi_value privatekey_publickey_ciphertext;
  status = napi_get_named_property(env, privatekey_publickey, "ciphertext",
    &privatekey_publickey_ciphertext);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  uint8_t sk_pk_ciphertext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  size_t sk_pk_ciphertext_len;

  status = napi_get_buffer_info(env, privatekey_publickey_ciphertext,
    (void**) &sk_pk_ciphertext, &sk_pk_ciphertext_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  // picnic_publickey_t sk_pk = {
  //   .params = (picnic_params_t) sk_pk_params,
  //   .plaintext = *sk_pk_plaintext,
  //   .ciphertext = *sk_pk_ciphertext
  // };
  picnic_publickey_t sk_pk = {
    .params = (picnic_params_t) sk_pk_params
  };
  memcpy((void*) sk_pk.plaintext, (void*) sk_pk_plaintext,
    (size_t) PICNIC_MAX_LOWMC_BLOCK_SIZE);
  memcpy((void*) sk_pk.ciphertext, (void*) sk_pk_ciphertext,
    (size_t) PICNIC_MAX_LOWMC_BLOCK_SIZE);

  // picnic_privatekey_t sk = {
  //   .params = (picnic_params_t) sk_params,
  //   .data = *sk_data,
  //   .pk = sk_pk
  // };
  picnic_privatekey_t sk = {
    .params = (picnic_params_t) sk_params,
    .pk = sk_pk
  };
  memcpy((void*) sk.data, (void*) sk_data,
    (size_t) PICNIC_MAX_LOWMC_BLOCK_SIZE);

  // getting napi_value argv[1] as uint8_t msg[], its length first
  napi_value message_length;
  status = napi_get_named_property(env, argv[1], "length", &message_length);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int msg_length;
  status = napi_get_value_int32(env, message_length, &msg_length);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  size_t msg_len;
  void* msg = malloc(msg_length * sizeof(uint8_t));
  if (msg == NULL) napi_throw_error(env, NULL, "malloc failed");

  status = napi_get_buffer_info(env, argv[1], (void**) &msg, &msg_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  size_t req_sig_len = picnic_signature_size(sk.params);
  size_t sig_len;

  uint8_t* sig = (uint8_t*) malloc(req_sig_len * sizeof(uint8_t));
  if (sig == NULL) napi_throw_error(env, NULL, "malloc failed");

  // signing
  int code = picnic_sign(&sk, msg, msg_len, sig, &sig_len);
  THROW_MAYBE(env, code, "picnic_sign failed");

  // passing the signature back to node
  napi_value signature;
  void* signature_buffer = malloc(sig_len * sizeof(uint8_t));
  if (signature_buffer == NULL) napi_throw_error(env, NULL, "malloc failed");

  status = napi_create_buffer_copy(env, sig_len, (void*) sig,
    (void**) &signature_buffer, &signature);
  THROW_MAYBE(env, status, "napi_create_buffer_copy failed");

  free(sig); // seems I cant free msg and signature_buffer

  return signature;
}

// args:: publickey:Object, message:Buffer, signature:Buffer
napi_value verify_wrapper (napi_env env, napi_callback_info info) {
  napi_status status;

  size_t argc = 3;
  napi_value argv[3];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  THROW_MAYBE(env, status, "napi_get_cb_info failed");

  // getting argv[1] as picnic_publickey_t pk
  napi_value publickey_params;
  status = napi_get_named_property(env, argv[0], "params", &publickey_params);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int pk_params;
  status = napi_get_value_int32(env, publickey_params, &pk_params);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  napi_value publickey_plaintext;
  status = napi_get_named_property(env, argv[0], "plaintext",
    &publickey_plaintext);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  // uint8_t pk_plaintext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  uint8_t* pk_plaintext;
  size_t pk_plaintext_len;

  status = napi_get_buffer_info(env, publickey_plaintext,
    (void**) &pk_plaintext, &pk_plaintext_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  napi_value publickey_ciphertext;
  status = napi_get_named_property(env, argv[0], "ciphertext",
    &publickey_ciphertext);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  // uint8_t pk_ciphertext[PICNIC_MAX_LOWMC_BLOCK_SIZE];
  uint8_t* pk_ciphertext;
  size_t pk_ciphertext_len;

  status = napi_get_buffer_info(env, publickey_ciphertext,
    (void**) &pk_ciphertext, &pk_ciphertext_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  // memcpy instead of dereferencing arrays
  // picnic_publickey_t pk = {
  //   .params = (picnic_params_t) pk_params,
  //   .plaintext = *pk_plaintext,
  //   .ciphertext = *pk_ciphertext
  // };
  picnic_publickey_t pk = {
    .params = (picnic_params_t) pk_params
  };
  memcpy((void*) pk.plaintext, (void*) pk_plaintext,
    (size_t) PICNIC_MAX_LOWMC_BLOCK_SIZE);
  memcpy((void*) pk.ciphertext, (void*) pk_ciphertext,
    (size_t) PICNIC_MAX_LOWMC_BLOCK_SIZE);

  // getting napi_value argv[1] as uint8_t msg[], its length first
  napi_value message_length;
  status = napi_get_named_property(env, argv[1], "length", &message_length);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int msg_length;
  status = napi_get_value_int32(env, message_length, &msg_length);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  uint8_t* msg;
  // uint8_t* msg = (uint8_t*) malloc(msg_length * sizeof(uint8_t));
  // if (msg == NULL) napi_throw_error(env, NULL, "malloc failed");
  size_t msg_len;

  status = napi_get_buffer_info(env, argv[1], (void**) &msg, &msg_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  napi_value signature_length;
  status = napi_get_named_property(env, argv[2], "length", &signature_length);
  THROW_MAYBE(env, status, "napi_get_named_property failed");

  int sig_length;
  status = napi_get_value_int32(env, signature_length, &sig_length);
  THROW_MAYBE(env, status, "napi_get_value_int32 failed");

  uint8_t* sig;
  // uint8_t* sig = (uint8_t*) malloc(sig_length * sizeof(uint8_t));
  // if (sig == NULL) napi_throw_error(env, NULL, "malloc failed");
  size_t sig_len;

  status = napi_get_buffer_info(env, argv[2], (void**) &sig, &sig_len);
  THROW_MAYBE(env, status, "napi_get_buffer_info failed");

  // DEBUG START
  printf("\npublickey::");
  printf("\nparams: %d", pk.params);
  printf("\nplaintext: ");
  for (size_t i = 0; i < PICNIC_MAX_LOWMC_BLOCK_SIZE; i++) {
    printf("%d ", pk.plaintext[i]);
  }
  printf("\nciphertext: ");
  for (size_t i = 0; i < PICNIC_MAX_LOWMC_BLOCK_SIZE; i++) {
    printf("%d ", pk.ciphertext[i]);
  }
  printf("\nmessage: ");
  for (size_t i = 0; i < msg_len; i++) {
    printf("%d ", msg[i]);
  }
  printf("\nsignature head: ");
  for (size_t i = 0; i < 250; i++) {
    printf("%d ", (int) sig[i]);
  }
  printf("\nmsg_len: %d", (int) msg_len);
  printf("\nsig_len: %d", (int) sig_len);
  printf("\n");
  // DEBUG END

  // invalid signature - does not verify
  // int code = picnic_verify(&pk, (uint8_t*) msg, msg_len, (uint8_t*) sig,
  //   sig_len);
  int code = picnic_verify(&pk, msg, msg_len, sig, sig_len);
  THROW_MAYBE(env, code, "picnic_verify failed");

  napi_value exitcode;
  status = napi_create_int32(env, code, &exitcode);
  THROW_MAYBE(env, status, "napi_create_int32 failed");

  return exitcode;
}

napi_value init (napi_env env, napi_value exports) {
  napi_status status;

  napi_value getParamName_export;
  status = napi_create_function(env, NULL, 0, getParamName, NULL,
    &getParamName_export);
  THROW_MAYBE(env, status, "napi_create_function failed");

  status = napi_set_named_property(env, exports, "getParamName",
    getParamName_export);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value signatureSize_export;
  status = napi_create_function(env, NULL, 0, signatureSize, NULL,
    &signatureSize_export);
  THROW_MAYBE(env, status, "napi_create_function failed");

  status = napi_set_named_property(env, exports, "signatureSize",
    signatureSize_export);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value keygen_export;
  status = napi_create_function(env, NULL, 0, keygen, NULL, &keygen_export);
  THROW_MAYBE(env, status, "napi_create_function failed");

  status = napi_set_named_property(env, exports, "keygen", keygen_export);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value sign_wrapper_export;
  status = napi_create_function(env, NULL, 0, sign_wrapper, NULL,
    &sign_wrapper_export);
  THROW_MAYBE(env, status, "napi_create_function failed");

  status = napi_set_named_property(env, exports, "sign", sign_wrapper_export);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  napi_value verify_wrapper_export;
  status = napi_create_function(env, NULL, 0, verify_wrapper, NULL,
    &verify_wrapper_export);
  THROW_MAYBE(env, status, "napi_create_function failed");

  status = napi_set_named_property(env, exports, "verify",
    verify_wrapper_export);
  THROW_MAYBE(env, status, "napi_set_named_property failed");

  // public picnic API surface...
  // ...

  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, init);

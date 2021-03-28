#include <node_api.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "type.h"
#include "dazoe_ed25519/ed25519/ed25519.h"

napi_value make_keypair_sync(napi_env env, napi_callback_info info) {
  napi_status status;
  
  napi_value ret_dummy;
  status = napi_create_int32(env, 0, &ret_dummy);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_dummy");
    return ret_dummy;
  }
  
  size_t argc = 3;
  napi_value argv[3];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  // seed
  u8 *data_src;
  size_t data_src_len;
  status = napi_get_buffer_info(env, argv[0], (void**)&data_src, &data_src_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src");
    return ret_dummy;
  }
  
  u8 *data_dst_pub;
  size_t data_dst_pub_len;
  status = napi_get_buffer_info(env, argv[1], (void**)&data_dst_pub, &data_dst_pub_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst_pub");
    return ret_dummy;
  }
  
  u8 *data_dst_prv;
  size_t data_dst_prv_len;
  status = napi_get_buffer_info(env, argv[2], (void**)&data_dst_prv, &data_dst_prv_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst_prv");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (data_dst_pub_len != 32) {
    printf("data_dst_pub_len %ld\n", data_dst_pub_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst_pub; length != 32");
    return ret_dummy;
  }
  if (data_dst_prv_len != 64) {
    printf("data_dst_prv_len %ld\n", data_dst_prv_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst_prv; length != 64");
    return ret_dummy;
  }
  memcpy(data_dst_prv, data_src, 32);
  
  crypto_sign_keypair(data_dst_pub, data_dst_prv);
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  return ret_dummy;
}

napi_value sign_pk_sync(napi_env env, napi_callback_info info) {
  napi_status status;
  
  napi_value ret_dummy;
  status = napi_create_int32(env, 0, &ret_dummy);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_dummy");
    return ret_dummy;
  }
  
  size_t argc = 3;
  napi_value argv[3];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  // message
  u8 *data_src;
  size_t data_src_len;
  status = napi_get_buffer_info(env, argv[0], (void**)&data_src, &data_src_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src");
    return ret_dummy;
  }
  
  // prv key
  u8 *data_src_key;
  size_t data_src_key_len;
  status = napi_get_buffer_info(env, argv[1], (void**)&data_src_key, &data_src_key_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key");
    return ret_dummy;
  }
  
  // signature
  u8 *data_dst;
  size_t data_dst_len;
  status = napi_get_buffer_info(env, argv[2], (void**)&data_dst, &data_dst_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (data_src_key_len != 64) {
    printf("data_src_key_len %ld\n", data_src_key_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key; length != 64");
    return ret_dummy;
  }
  if (data_dst_len != 64) {
    printf("data_dst_len %ld\n", data_dst_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst; length != 64");
    return ret_dummy;
  }
  unsigned long long sig_len = 64 + data_src_len;
  u8* tmp_buf = (u8*)malloc(sig_len);
  crypto_sign(tmp_buf, &sig_len, data_src, data_src_len, data_src_key);
  memcpy(data_dst, tmp_buf, data_dst_len);
  free(tmp_buf);
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  return ret_dummy;
}

napi_value verify_sync(napi_env env, napi_callback_info info) {
  napi_status status;
  
  napi_value ret_dummy;
  status = napi_create_int32(env, 0, &ret_dummy);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_dummy");
    return ret_dummy;
  }
  
  size_t argc = 3;
  napi_value argv[3];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  // message
  u8 *data_src;
  size_t data_src_len;
  status = napi_get_buffer_info(env, argv[0], (void**)&data_src, &data_src_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src");
    return ret_dummy;
  }
  
  // signature
  u8 *data_src_sign;
  size_t data_src_sign_len;
  status = napi_get_buffer_info(env, argv[1], (void**)&data_src_sign, &data_src_sign_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_sign");
    return ret_dummy;
  }
  
  // pub key
  u8 *data_src_key;
  size_t data_src_key_len;
  status = napi_get_buffer_info(env, argv[2], (void**)&data_src_key, &data_src_key_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key");
    return ret_dummy;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (data_src_key_len != 32) {
    printf("data_src_key_len %ld\n", data_src_key_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key; length != 32");
    return ret_dummy;
  }
  if (data_src_sign_len != 64) {
    printf("data_src_sign_len %ld\n", data_src_sign_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_sign; length != 64");
    return ret_dummy;
  }
  
  int verify_result = crypto_sign_verify(data_src_sign, data_src, data_src_len, data_src_key) == 0;
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  
  napi_value ret_value;
  status = napi_create_int32(env, verify_result, &ret_value);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_value");
    return ret_dummy;
  }
  
  return ret_value;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
struct Verify_work_data {
  u8* data_src;
  size_t data_src_len;
  u8* data_src_sign;
  size_t data_src_sign_len;
  u8* data_src_key;
  size_t data_src_key_len;
  
  const char* error;
  int verify_result;
  napi_ref callback_reference;
};
void verify_work_data_free(struct Verify_work_data* data) {
  free(data->data_src);
  free(data->data_src_sign);
  free(data->data_src_key);
  free(data);
}

void napi_helper_error_cb(napi_env env, const char* error_str, napi_value callback) {
  napi_status status;
  napi_value global;
  status = napi_get_global(env, &global);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create return value global (napi_get_global)");
    return;
  }
  
  napi_value call_argv[1];
  
  // napi_value error_code;
  // status = napi_create_int32(env, 1, &error_code);
  // if (status != napi_ok) {
    // printf("status = %d\n", status);
    // napi_throw_error(env, NULL, "!napi_create_int32");
    // return;
  // }
  
  napi_value error;
  status = napi_create_string_utf8(env, error_str, strlen(error_str), &error);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "!napi_create_string_utf8");
    return;
  }
  
  status = napi_create_error(env,
    NULL,
    error,
    &call_argv[0]);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    printf("error  = %s\n", error_str);
    napi_throw_error(env, NULL, "!napi_create_error");
    return;
  }
  
  napi_value result;
  status = napi_call_function(env, global, callback, 1, call_argv, &result);
  if (status != napi_ok) {
    // это нормальная ошибка если основной поток падает
    napi_throw_error(env, NULL, "!napi_call_function");
    return;
  }
  return;
}

void execute_verify(napi_env env, void* _data) {
  struct Verify_work_data* data = (struct Verify_work_data*)_data;
  data->verify_result = crypto_sign_verify(data->data_src_sign, data->data_src, data->data_src_len, data->data_src_key) == 0;
}

void complete_verify(napi_env env, napi_status execute_status, void* _data) {
  napi_status status;
  struct Verify_work_data* worker_ctx = (struct Verify_work_data*)_data;
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  //    prepare for callback (common parts)
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  napi_value callback;
  status = napi_get_reference_value(env, worker_ctx->callback_reference, &callback);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to get referenced callback (napi_get_reference_value)");
    verify_work_data_free(worker_ctx);
    return;
  }
  napi_value data_dst_val;
  status = napi_create_int32(env, worker_ctx->verify_result, &data_dst_val);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create return value data_dst_val");
    verify_work_data_free(worker_ctx);
    return;
  }
  
  
  napi_value global;
  status = napi_get_global(env, &global);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create return value global (napi_get_global)");
    verify_work_data_free(worker_ctx);
    return;
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (execute_status != napi_ok) {
    // чтобы не дублировать код
    if (!worker_ctx->error) {
      worker_ctx->error = "execute_status != napi_ok";
    }
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (worker_ctx->error) {
    napi_helper_error_cb(env, worker_ctx->error, callback);
    verify_work_data_free(worker_ctx);
    return;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  //    callback OK
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  napi_value result;
  napi_value call_argv[2];
  napi_get_null(env, &call_argv[0]);
  call_argv[1] = data_dst_val;
  
  status = napi_call_function(env, global, callback, 2, call_argv, &result);
  if (status != napi_ok) {
    fprintf(stderr, "status = %d\n", status);
    napi_throw_error(env, NULL, "napi_call_function FAIL");
    verify_work_data_free(worker_ctx);
    return;
  }
  verify_work_data_free(worker_ctx);
}



napi_value verify(napi_env env, napi_callback_info info) {
  napi_status status;
  
  napi_value ret_dummy;
  status = napi_create_int32(env, 0, &ret_dummy);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_dummy");
    return ret_dummy;
  }
  
  size_t argc = 4;
  napi_value argv[4];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
    return ret_dummy;
  }
  
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  // message
  u8 *data_src;
  size_t data_src_len;
  status = napi_get_buffer_info(env, argv[0], (void**)&data_src, &data_src_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src");
    return ret_dummy;
  }
  
  // signature
  u8 *data_src_sign;
  size_t data_src_sign_len;
  status = napi_get_buffer_info(env, argv[1], (void**)&data_src_sign, &data_src_sign_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_sign");
    return ret_dummy;
  }
  
  // pub key
  u8 *data_src_key;
  size_t data_src_key_len;
  status = napi_get_buffer_info(env, argv[2], (void**)&data_src_key, &data_src_key_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key");
    return ret_dummy;
  }
  
  napi_value callback = argv[3];
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (data_src_key_len != 32) {
    printf("data_src_key_len %ld\n", data_src_key_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key; length != 32");
    return ret_dummy;
  }
  if (data_src_sign_len != 64) {
    printf("data_src_sign_len %ld\n", data_src_sign_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_sign; length != 64");
    return ret_dummy;
  }
  
  struct Verify_work_data* worker_ctx = (struct Verify_work_data*)malloc(sizeof(struct Verify_work_data));
  worker_ctx->error = NULL;
  
  worker_ctx->data_src = (u8*)malloc(data_src_len);
  memcpy(worker_ctx->data_src, data_src, data_src_len);
  worker_ctx->data_src_len = data_src_len;
  
  worker_ctx->data_src_key = (u8*)malloc(data_src_key_len);
  memcpy(worker_ctx->data_src_key, data_src_key, data_src_key_len);
  worker_ctx->data_src_key_len = data_src_key_len;
  
  worker_ctx->data_src_sign = (u8*)malloc(data_src_sign_len);
  memcpy(worker_ctx->data_src_sign, data_src_sign, data_src_sign_len);
  worker_ctx->data_src_sign_len = data_src_sign_len;
  
  
  status = napi_create_reference(env, callback, 1, &worker_ctx->callback_reference);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create reference for callback. napi_create_reference");
    verify_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  napi_value async_resource_name;
  status = napi_create_string_utf8(env, "dummy", 5, &async_resource_name);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create value async_resource_name set to \"dummy\"");
    verify_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  napi_async_work work;
  status = napi_create_async_work(env,
                                   NULL,
                                   async_resource_name,
                                   execute_verify,
                                   complete_verify,
                                   (void*)worker_ctx,
                                   &work);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "napi_create_async_work fail");
    verify_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  status = napi_queue_async_work(env, work);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "napi_queue_async_work fail");
    verify_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  /*//////////////////////////////////////////////////////////////////////////////////////////////////*/
  return ret_dummy;
}


////////////////////////////////////////////////////////////////////////////////////////////////////
struct Sign_work_data {
  u8* data_src;
  size_t data_src_len;
  u8* data_src_key;
  size_t data_src_key_len;
  
  // обсчет ведется в другом потоке, там распаковывать reference нельзя/не желательно
  u8* data_dst;
  size_t data_dst_len;
  
  const char* error;
  napi_ref data_dst_reference;
  napi_ref callback_reference;
};
void sign_work_data_free(struct Sign_work_data* data) {
  free(data->data_src);
  free(data->data_src_key);
  free(data->data_dst);
  free(data);
}


void execute_sign_pk(napi_env env, void* _data) {
  struct Sign_work_data* data = (struct Sign_work_data*)_data;
  
  unsigned long long sig_len = 64 + data->data_src_len;
  u8* tmp_buf = (u8*)malloc(sig_len);
  crypto_sign(tmp_buf, &sig_len, data->data_src, data->data_src_len, data->data_src_key);
  memcpy(data->data_dst, tmp_buf, data->data_dst_len);
  free(tmp_buf);
}

void complete_sign_pk(napi_env env, napi_status execute_status, void* _data) {
  napi_status status;
  struct Sign_work_data* worker_ctx = (struct Sign_work_data*)_data;
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  //    prepare for callback (common parts)
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  napi_value callback;
  status = napi_get_reference_value(env, worker_ctx->callback_reference, &callback);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to get referenced callback (napi_get_reference_value)");
    sign_work_data_free(worker_ctx);
    return;
  }
  napi_value data_dst_val;
  status = napi_get_reference_value(env, worker_ctx->data_dst_reference, &data_dst_val);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to get referenced callback (napi_get_reference_value)");
    sign_work_data_free(worker_ctx);
    return;
  }
  u8 *data_dst;
  size_t data_dst_len;
  status = napi_get_buffer_info(env, data_dst_val, (void**)&data_dst, &data_dst_len);
  
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst");
    sign_work_data_free(worker_ctx);
    return;
  }
  
  
  napi_value global;
  status = napi_get_global(env, &global);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create return value global (napi_get_global)");
    sign_work_data_free(worker_ctx);
    return;
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (execute_status != napi_ok) {
    // чтобы не дублировать код
    if (!worker_ctx->error) {
      worker_ctx->error = "execute_status != napi_ok";
    }
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (worker_ctx->error) {
    napi_helper_error_cb(env, worker_ctx->error, callback);
    sign_work_data_free(worker_ctx);
    return;
  }
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  //    callback OK
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  napi_value result;
  napi_value call_argv[0];
  
  memcpy(data_dst, worker_ctx->data_dst, data_dst_len);
  
  status = napi_call_function(env, global, callback, 0, call_argv, &result);
  if (status != napi_ok) {
    fprintf(stderr, "status = %d\n", status);
    napi_throw_error(env, NULL, "napi_call_function FAIL");
    sign_work_data_free(worker_ctx);
    return;
  }
  sign_work_data_free(worker_ctx);
}



napi_value sign_pk(napi_env env, napi_callback_info info) {
  napi_status status;
  
  napi_value ret_dummy;
  status = napi_create_int32(env, 0, &ret_dummy);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to create return value ret_dummy");
    return ret_dummy;
  }
  
  size_t argc = 4;
  napi_value argv[4];
  status = napi_get_cb_info(env, info, &argc, argv, NULL, NULL);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Failed to parse arguments");
    return ret_dummy;
  }
  
  
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  // message
  u8 *data_src;
  size_t data_src_len;
  status = napi_get_buffer_info(env, argv[0], (void**)&data_src, &data_src_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src");
    return ret_dummy;
  }
  
  // prv key
  u8 *data_src_key;
  size_t data_src_key_len;
  status = napi_get_buffer_info(env, argv[1], (void**)&data_src_key, &data_src_key_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key");
    return ret_dummy;
  }
  
  // signature
  u8 *data_dst;
  size_t data_dst_len;
  status = napi_get_buffer_info(env, argv[2], (void**)&data_dst, &data_dst_len);
  
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst");
    return ret_dummy;
  }
  napi_value data_dst_val = argv[2];
  
  napi_value callback = argv[3];
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  if (data_src_key_len != 64) {
    printf("data_src_key_len %ld\n", data_src_key_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_src_key; length != 64");
    return ret_dummy;
  }
  if (data_dst_len != 64) {
    printf("data_dst_len %ld\n", data_dst_len);
    napi_throw_error(env, NULL, "Invalid buffer was passed as argument of data_dst; length != 64");
    return ret_dummy;
  }
  
  struct Sign_work_data* worker_ctx = (struct Sign_work_data*)malloc(sizeof(struct Sign_work_data));
  worker_ctx->error = NULL;
  
  worker_ctx->data_src = (u8*)malloc(data_src_len);
  memcpy(worker_ctx->data_src, data_src, data_src_len);
  worker_ctx->data_src_len = data_src_len;
  
  worker_ctx->data_src_key = (u8*)malloc(data_src_key_len);
  memcpy(worker_ctx->data_src_key, data_src_key, data_src_key_len);
  worker_ctx->data_src_key_len = data_src_key_len;
  
  worker_ctx->data_dst = (u8*)malloc(data_dst_len);
  worker_ctx->data_dst_len = data_dst_len;
  
  status = napi_create_reference(env, callback, 1, &worker_ctx->callback_reference);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create reference for callback. napi_create_reference");
    sign_work_data_free(worker_ctx);
    return ret_dummy;
  }
  /* EXTRA */
  status = napi_create_reference(env, data_dst_val, 1, &worker_ctx->data_dst_reference);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create reference for callback. napi_create_reference");
    sign_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  napi_value async_resource_name;
  status = napi_create_string_utf8(env, "dummy", 5, &async_resource_name);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "Unable to create value async_resource_name set to \"dummy\"");
    sign_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  napi_async_work work;
  status = napi_create_async_work(env,
                                   NULL,
                                   async_resource_name,
                                   execute_sign_pk,
                                   complete_sign_pk,
                                   (void*)worker_ctx,
                                   &work);
  if (status != napi_ok) {
    printf("status = %d\n", status);
    napi_throw_error(env, NULL, "napi_create_async_work fail");
    sign_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  status = napi_queue_async_work(env, work);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "napi_queue_async_work fail");
    sign_work_data_free(worker_ctx);
    return ret_dummy;
  }
  
  /*//////////////////////////////////////////////////////////////////////////////////////////////////*/
  return ret_dummy;
}

////////////////////////////////////////////////////////////////////////////////////////////////////

napi_value Init(napi_env env, napi_value exports) {
  napi_status status;
  napi_value fn;
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  status = napi_create_function(env, NULL, 0, make_keypair_sync, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }
  
  status = napi_set_named_property(env, exports, "make_keypair_sync", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  status = napi_create_function(env, NULL, 0, sign_pk_sync, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }
  
  status = napi_set_named_property(env, exports, "sign_pk_sync", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  status = napi_create_function(env, NULL, 0, sign_pk, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }
  
  status = napi_set_named_property(env, exports, "sign_pk", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  status = napi_create_function(env, NULL, 0, verify_sync, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }
  
  status = napi_set_named_property(env, exports, "verify_sync", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  status = napi_create_function(env, NULL, 0, verify, NULL, &fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to wrap native function");
  }
  
  status = napi_set_named_property(env, exports, "verify", fn);
  if (status != napi_ok) {
    napi_throw_error(env, NULL, "Unable to populate exports");
  }
  ////////////////////////////////////////////////////////////////////////////////////////////////////
  
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, Init)

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "org_bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"
#include "include/secp256k1_ecdh.h"
#include "include/secp256k1_recovery.h"


SECP256K1_API jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ctx_1clone
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  const secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

  jlong ctx_clone_l = (uintptr_t) secp256k1_context_clone(ctx);

  (void)classObject;(void)env;

  return ctx_clone_l;

}

SECP256K1_API jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1context_1randomize
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context *ctx = (secp256k1_context*)(uintptr_t)ctx_l;

  const unsigned char* seed = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	int sigLen = *((int*)(data + 32));
	int pubLen = *((int*)(data + 32 + 4));

	return secp256k1_ecdsa_verify(data, 32, data+32+8, sigLen, data+32+8+sigLen, pubLen);
}

static void __javasecp256k1_attach(void) __attribute__((constructor));
static void __javasecp256k1_detach(void) __attribute__((destructor));

static void __javasecp256k1_attach(void) {
	secp256k1_start(SECP256K1_START_VERIFY);
}

static void __javasecp256k1_detach(void) {
	secp256k1_stop();
}

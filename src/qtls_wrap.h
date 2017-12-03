#ifndef SRC_QTLS_WRAP_H_
#define SRC_QTLS_WRAP_H_

#if defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS

#include "node.h"
#include "node_crypto.h" // SSLWrap

#include "async-wrap.h"
#include "env.h"
#include "util.h"
#include "v8.h"

#include <openssl/ssl.h>

namespace node
{

namespace crypto
{
  class SecureContext;
  class NodeBIO;
}

class QTLSWrap : public AsyncWrap,
                 public crypto::SSLWrap<QTLSWrap>
{

public:
  ~QTLSWrap() override;

protected:
  static const int kInitialClientBufferLength = 4096;


  QTLSWrap(Environment *env, SecureContext *sc, Kind kind);
  InitSSL();
  static void Initialize(v8::Local<v8::Object> target,
                         v8::Local<v8::Value> unused,
                         v8::Local<v8::Context> context);

  ////////////////////////////////////////////////
  //            SSL Callback methods            //
  ////////////////////////////////////////////////
  int AddTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                         unsigned int content, const unsigned char **out,
                         size_t *outlen, X509 *x, size_t chainidx, int *al,
                         void *add_arg);
  void FreeTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                           unsigned int context, const unsigned char *out,
                           void *add_arg);
  int ParseTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                           unsigned int context, const unsigned char *in,
                           size_t inlen, X509 *x, size_t chainidx, int *al,
                           void *parse_arg);
  void SSLInfoCallback(const SSL *ssl_, int where, int ret);


  ////////////////////////////////////////////////
  //            mehods for JS land              //
  ////////////////////////////////////////////////
  static void Wrap(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void Start(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void SetTransportParams(const v8::FunctionCallbackInfo<v8::Value>& args);

private:
  crypto::SecureContext *sc_;
  BIO *enc_in_;
  BIO *enc_out_;
  bool _started;
};

} // namespace node

#endif // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif // SRC_QTLS_WRAP_H_

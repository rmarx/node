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

  size_t self_size() const override { return sizeof(*this); }
  void NewSessionDoneCb();


  static void Initialize(v8::Local<v8::Object> target,
                         v8::Local<v8::Value> unused,
                         v8::Local<v8::Context> context);

protected:
  static const int kInitialClientBufferLength = 4096;


  QTLSWrap(Environment *env, crypto::SecureContext *sc, Kind kind);
  void InitSSL();

  ////////////////////////////////////////////////
  //            SSL Callback methods            //
  ////////////////////////////////////////////////
  static int AddTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                         unsigned int content, const unsigned char **out,
                         size_t *outlen, X509 *x, size_t chainidx, int *al,
                         void *add_arg);
  static void FreeTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                           unsigned int context, const unsigned char *out,
                           void *add_arg);
  static int ParseTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                           unsigned int context, const unsigned char *in,
                           size_t inlen, X509 *x, size_t chainidx, int *al,
                           void *parse_arg);
  static void SSLInfoCallback(const SSL *ssl_, int where, int ret);


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
  bool started_;

  unsigned char* transport_parameters;
  size_t transport_parameters_length;
};

} // namespace node

#endif // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif // SRC_QTLS_WRAP_H_

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
  // If |msg| is not nullptr, caller is responsible for calling `delete[] *msg`.
  v8::Local<v8::Value> GetSSLError(int status, int* err, const char** msg);


  ////////////////////////////////////////////////
  //            SSL Callback methods            //
  ////////////////////////////////////////////////
  static crypto::SecureContext* AddContextCallbacks(crypto::SecureContext *sc, Kind kind);
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
  
protected:
  static const int kInitialClientBufferLength = 4096;


  QTLSWrap(Environment *env, crypto::SecureContext *sc, Kind kind);
  void InitSSL();


  ////////////////////////////////////////////////
  //            mehods for JS land              //
  ////////////////////////////////////////////////
  static void Wrap(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GetClientInitial(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void WriteHandshakeData(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void WriteEarlyData(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ReadHandshakeData(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ReadEarlyData(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ReadSSL(const v8::FunctionCallbackInfo<v8::Value> &args);
  static void EnableSessionCallbacks(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void SetTransportParams(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GetTransportParams(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void SetVerifyMode(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void DestroySSL(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ExportKeyingMaterial(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void ExportEarlyKeyingMaterial(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void IsEarlyDataAllowed(const v8::FunctionCallbackInfo<v8::Value>& args);
  static void GetNegotiatedCipher(const v8::FunctionCallbackInfo<v8::Value>& args);

private:
  crypto::SecureContext *sc_;
  BIO *enc_in_;
  BIO *enc_out_;
  bool started_;

  unsigned char* local_transport_parameters;
  size_t local_transport_parameters_length;
  unsigned char* remote_transport_parameters;
  size_t remote_transport_parameters_length;
};

} // namespace node

#endif // defined(NODE_WANT_INTERNALS) && NODE_WANT_INTERNALS
#endif // SRC_QTLS_WRAP_H_

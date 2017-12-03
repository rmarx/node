#include "qtls_wrap.h"
#include "async-wrap.h"
#include "async-wrap-inl.h"
#include "node_buffer.h"             // Buffer
#include "node_crypto.h"             // SecureContext
#include "node_crypto_bio.h"         // NodeBIO
#include "node_crypto_clienthello.h" // ClientHelloParser
#include "node_crypto_clienthello-inl.h"
#include "node_counters.h"
#include "node_internals.h"
#include "stream_base.h"
#include "stream_base-inl.h"

namespace node
{

using crypto::SSLWrap;
using crypto::SecureContext;
using v8::Context;
using v8::EscapableHandleScope;
using v8::Exception;
using v8::Function;
using v8::FunctionCallbackInfo;
using v8::FunctionTemplate;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

void QTLSWrap::Initialize(Local<Object> target,
                          Local<Value> unused,
                          Local<Context> context)
{
  Environment *env = Environment::GetCurrent(context);

  env->SetMethod(target, "wrap", QTLSWrap::Wrap);

  auto constructor = [](const FunctionCallbackInfo<Value> &args) {
    CHECK(args.IsConstructCall());
    args.This()->SetAlignedPointerInInternalField(0, nullptr);
  };

  Local<String> qtlsWrapString =
      FIXED_ONE_BYTE_STRING(env->isolate(), "QTLSWrap");

  auto t = env->NewFunctionTemplate(constructor);
  t->InstanceTemplate()->SetInternalFieldCount(1);
  t->SetClassName(qtlsWrapString);

  AsyncWrap::AddWrapMethods(env, t, AsyncWrap::kFlagHasReset);
  // example: env->SetProtoMethod(t, "receive", Receive);
  env->SetProtoMethod(t, "start", Start);

  SSLWrap<TLSWrap>::AddMethods(env, t);

  env->set_qtls_wrap_constructor_function(t->GetFunction());

  target->Set(qtlsWrapString, t->GetFunction());
}

QTLSWrap::QTLSWrap(Environment *env, SecureContext *sc, Kind kind)
    : AsyncWrap(env,
                env->tls_wrap_constructor_function()
                    ->NewInstance(env->context())
                    .ToLocalChecked(),
                AsyncWrap::PROVIDER_QTLSWRAP),
      SSLWrap<TLSWrap>(env, sc, kind),
      sc_(sc),
      started_(false)
{
  node::Wrap(object(), this);
  MakeWeak(this);

  // sc comes from an Unwrap. Make sure it was assigned.
  CHECK_NE(sc, nullptr);

  // We've our own session callbacks
  SSL_CTX_sess_set_get_cb(sc_->ctx_, SSLWrap<TLSWrap>::GetSessionCallback);
  SSL_CTX_sess_set_new_cb(sc_->ctx_, SSLWrap<TLSWrap>::NewSessionCallback);

  InitSSL();
}

void QTLSWrap::InitSSL()
{
  // Initialize SSL
  enc_in_ = crypto::NodeBIO::New();
  enc_out_ = crypto::NodeBIO::New();
  crypto::NodeBIO::FromBIO(enc_in_)->AssignEnvironment(env());
  crypto::NodeBIO::FromBIO(enc_out_)->AssignEnvironment(env());

  SSL_set_bio(ssl_, enc_in_, enc_out_);

  SSL_set_app_data(ssl_, this);
  SSL_set_info_callback(ssl_, SSLInfoCallback);
  SSL_CTX_set_mode(_sc->_ctx, SSL_MODE_RELEASE_BUFFERS);
  SSL_CTX_set_min_proto_version(_sc->_ctx, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(_sc->_ctx, TLS1_3_VERSION);

  SSL_set_cert_cb(ssl_, SSLWrap<TLSWrap>::SSLCertCallback, this);

  SSL_CTX_add_custom_ext(_sc->_ctx, 26,
                         SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS |
                             SSL_EXT_TLS1_3_NEW_SESSION_TICKET | SSL_EXT_IGNORE_ON_RESUMPTION,
                         AddTransportParamsCallback, FreeTransportParamsCallback, nullptr,
                         ParseTransportParamsCallback, nullptr);
  if (is_server())
  {
    SSL_set_accept_state(ssl_);
  }
  else if (is_client())
  {
    // Enough space for server response (hello, cert)
    crypto::NodeBIO::FromBIO(enc_in_)->set_initial(kInitialClientBufferLength);
    SSL_set_connect_state(ssl_);
  }
  else
  {
    // Unexpected
    ABORT();
  }
}

////////////////////////////////////////////////
//            SSL Callback methods            //
////////////////////////////////////////////////
int QTLSWrap::AddTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                         unsigned int content, const unsigned char **out,
                                         size_t *outlen, X509 *x, size_t chainidx, int *al,
                                         void *add_arg)
{
  // add transport parameters
}

void QTLSWrap::FreeTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                           unsigned int context, const unsigned char *out,
                                           void *add_arg)
{
  delete[] const_cast<unsigned char *>(out);
}

int QTLSWrap::ParseTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                           unsigned int context, const unsigned char *in,
                                           size_t inlen, X509 *x, size_t chainidx, int *al,
                                           void *parse_arg)
{
  // parse transport params
  // probably call callback from JS land
}

void QTLSWrap::SSLInfoCallback(const SSL *ssl_, int where, int ret)
{
  if (!(where & (SSL_CB_HANDSHAKE_START | SSL_CB_HANDSHAKE_DONE)))
    return;

  // Be compatible with older versions of OpenSSL. SSL_get_app_data() wants
  // a non-const SSL* in OpenSSL <= 0.9.7e.
  SSL *ssl = const_cast<SSL *>(ssl_);
  QTLSWrap *c = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));
  Environment *env = c->env();
  Local<Object> object = c->object();

  if (where & SSL_CB_HANDSHAKE_START)
  {
    // On handshake start
  }

  if (where & SSL_CB_HANDSHAKE_DONE)
  {
    // handshake done
  }
}


void QTLSWrap::Wrap(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  if (args.Length() < 1 || !args[0]->IsObject())
  {
    return env->ThrowTypeError(
        "first argument should be a SecureContext instance");
  }
  if (args.Length() < 2 || !args[1]->IsBoolean())
    return env->ThrowTypeError("second argument should be boolean");

  Local<Object> sc = args[0].As<Object>();
  Kind kind = args[1]->IsTrue() ? SSLWrap<QTLSWrap>::kServer : SSLWrap<QTLSWrap>::kClient;

  QTLSWrap *res = new QTLSWrap(env, Unwrap<SecureContext>(sc), kind);

  args.GetReturnValue().Set(res->object());
}

void QTLSWrap::Start(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (wrap->started_)
    return env->ThrowError("Already started.");
  wrap->started_ = true;

  // Send ClientHello handshake
  CHECK(wrap->is_client());
  int read = SSL_do_handshake(ssl_);
  // read enc_out_ bio and return this data
}

void QTLSWrap::SetTransportParams(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment* env = Environment::GetCurrent(args);
  
  if (args.Length() < 1 || !args[0]->IsUint8Array())
  {
    return env->ThrowTypeError("Argument must be a buffer");
  }

  const char* data = Buffer::Data(args[0]);
  size_t length = Buffer::Length(args[0]);
  //store data somewhere to write in addtransportparamscb
}

} // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(qtls_wrap, node::QTLSWrap::Initialize)

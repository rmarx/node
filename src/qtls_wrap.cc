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
#include <limits>

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
using v8::Handle;
using v8::Integer;
using v8::Local;
using v8::Object;
using v8::String;
using v8::Value;

QTLSWrap::~QTLSWrap()
{
  this->sc_ = nullptr;
  this->enc_in_ = nullptr;
  this->enc_out_ = nullptr;
}

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
  env->SetProtoMethod(t, "getClientInitial", GetClientInitial);
  env->SetProtoMethod(t, "setTransportParams", SetTransportParams);
  env->SetProtoMethod(t, "getTransportParams", GetTransportParams);
  env->SetProtoMethod(t, "setVerifyMode", SetVerifyMode);
  env->SetProtoMethod(t, "destroySSL", DestroySSL);
  env->SetProtoMethod(t, "writeHandshakeData", WriteHandshakeData);
  env->SetProtoMethod(t, "readHandshakeData", ReadHandshakeData);
  env->SetProtoMethod(t, "exportKeyingMaterial", ExportKeyingMaterial);
  env->SetProtoMethod(t, "getNegotiatedCipher", GetNegotiatedCipher);

  SSLWrap<QTLSWrap>::AddMethods(env, t);

  env->set_qtls_wrap_constructor_function(t->GetFunction());

  target->Set(qtlsWrapString, t->GetFunction());
}

QTLSWrap::QTLSWrap(Environment *env, SecureContext *sc, Kind kind)
    : AsyncWrap(env,
                env->qtls_wrap_constructor_function()
                    ->NewInstance(env->context())
                    .ToLocalChecked(),
                AsyncWrap::PROVIDER_QTLSWRAP),
      SSLWrap<QTLSWrap>(env, QTLSWrap::AddContextCallbacks(sc, kind), kind),
      sc_(sc),
      started_(false),
      local_transport_parameters(nullptr),
      local_transport_parameters_length(0),
      remote_transport_parameters(nullptr),
      remote_transport_parameters_length(0)
{
  node::Wrap(object(), this);
  MakeWeak(this);

  // sc comes from an Unwrap. Make sure it was assigned.
  CHECK_NE(sc, nullptr);

  InitSSL();
}

SecureContext* QTLSWrap::AddContextCallbacks(SecureContext *sc, Kind kind)
{

  SSL_CTX_add_custom_ext(sc->ctx_, 26,
                         SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                         QTLSWrap::AddTransportParamsCallback, QTLSWrap::FreeTransportParamsCallback, nullptr,
                         QTLSWrap::ParseTransportParamsCallback, nullptr);

  if (kind == kServer) {
    /**
     * set to ffffffff according to QUIC to enable 0-RTT
     */
    SSL_CTX_set_max_early_data(sc->ctx_, std::numeric_limits<uint32_t>::max());
  }

  // min version of QUIC (v1) is TLS 1.3
  SSL_CTX_set_min_proto_version(sc->ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(sc->ctx_, TLS1_3_VERSION);
  
  // We've our own session callbacks
  SSL_CTX_sess_set_get_cb(sc->ctx_, SSLWrap<QTLSWrap>::GetSessionCallback);
  SSL_CTX_sess_set_new_cb(sc->ctx_, SSLWrap<QTLSWrap>::NewSessionCallback);

  // We've our own session callbacks
  SSL_CTX_sess_set_get_cb(sc->ctx_, SSLWrap<QTLSWrap>::GetSessionCallback);
  SSL_CTX_sess_set_new_cb(sc->ctx_, SSLWrap<QTLSWrap>::NewSessionCallback);

  return sc;
}

void QTLSWrap::DestroySSL(const FunctionCallbackInfo<Value> &args)
{
  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  // Destroy the SSL structure and friends
  wrap->SSLWrap<QTLSWrap>::DestroySSL();
}

Local<Value> QTLSWrap::GetSSLError(int status, int *err, const char **msg)
{
  EscapableHandleScope scope(env()->isolate());

  // ssl_ is already destroyed in reading EOF by close notify alert.
  if (ssl_ == nullptr)
    return Local<Value>();

  *err = SSL_get_error(ssl_, status);
  switch (*err)
  {
  case SSL_ERROR_NONE:
  case SSL_ERROR_WANT_READ:
  case SSL_ERROR_WANT_WRITE:
  case SSL_ERROR_WANT_X509_LOOKUP:
    break;
  case SSL_ERROR_ZERO_RETURN:
    return scope.Escape(env()->zero_return_string());
    break;
  default:
  {
    CHECK(*err == SSL_ERROR_SSL || *err == SSL_ERROR_SYSCALL);

    BIO *bio = BIO_new(BIO_s_mem());
    ERR_print_errors(bio);

    BUF_MEM *mem;
    BIO_get_mem_ptr(bio, &mem);

    Local<String> message =
        OneByteString(env()->isolate(), mem->data, mem->length);
    Local<Value> exception = Exception::Error(message);

    if (msg != nullptr)
    {
      CHECK_EQ(*msg, nullptr);
      char *const buf = new char[mem->length + 1];
      memcpy(buf, mem->data, mem->length);
      buf[mem->length] = '\0';
      *msg = buf;
    }
    BIO_free_all(bio);

    return scope.Escape(exception);
  }
  }
  return Local<Value>();
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
  //SSL_CTX_set_mode(sc_->ctx_, SSL_MODE_RELEASE_BUFFERS);
  SSL_set_cert_cb(ssl_, SSLWrap<QTLSWrap>::SSLCertCallback, this);

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
void QTLSWrap::NewSessionDoneCb()
{
  // started cycle in tlswrap, but probably here nothing to do
}

////////////////////////////////////////////////
//            SSL Callback methods            //
////////////////////////////////////////////////
int QTLSWrap::AddTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                         unsigned int content, const unsigned char **out,
                                         size_t *outlen, X509 *x, size_t chainidx, int *al,
                                         void *add_arg)
{
  QTLSWrap *qtlsWrap = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));

  // add transport parameters
  if (qtlsWrap->local_transport_parameters == nullptr)
  {
    return 1;
  }

  *out = qtlsWrap->local_transport_parameters;
  *outlen = qtlsWrap->local_transport_parameters_length;

  return 1;
}

void QTLSWrap::FreeTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                           unsigned int context, const unsigned char *out,
                                           void *add_arg)
{
  if (out != nullptr) {
    delete[] const_cast<unsigned char *>(out);
  }
}

int QTLSWrap::ParseTransportParamsCallback(SSL *ssl, unsigned int ext_type,
                                           unsigned int context, const unsigned char *in,
                                           size_t inlen, X509 *x, size_t chainidx, int *al,
                                           void *parse_arg)
{
  QTLSWrap *qtlsWrap = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));
  // parse transport params
  // add transport parameters
  if (qtlsWrap->remote_transport_parameters != nullptr)
  {
    delete[] qtlsWrap->remote_transport_parameters;
    qtlsWrap->remote_transport_parameters = nullptr;
  }

  qtlsWrap->remote_transport_parameters = new unsigned char[inlen];
  memcpy(qtlsWrap->remote_transport_parameters, in, inlen);
  qtlsWrap->remote_transport_parameters_length = inlen;
  // probably call callback from JS land
  return 1;
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
    Local<Value> callback = object->Get(env->onhandshakedone_string());
    if (callback->IsFunction()) {
      c->MakeCallback(callback.As<Function>(), 0, nullptr);
    }
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

void QTLSWrap::GetClientInitial(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  // Send ClientHello handshake
  CHECK(wrap->is_client());
  // next call will return -1 because OpenSSL can't complete the handshake when it is just starting
  int read = SSL_do_handshake(wrap->ssl_);
  // Still need to check though if the error is SSL_ERROR_WANT_READ or SSL_ERROR_WANT_WRITE
  // if this is not the case, return error
  int err;
  const char *error_str = nullptr;
  Local<Value> arg = wrap->GetSSLError(read, &err, &error_str);
  if (!arg.IsEmpty())
  {
    wrap->MakeCallback(env->onerror_string(), 1, &arg);
    delete[] error_str;
    return;
  }
  int pending = BIO_pending(wrap->enc_out_);
  char *data = new char[pending];
  size_t write_size_ = crypto::NodeBIO::FromBIO(wrap->enc_out_)->Read(data, pending);

  /*
  // Code to call a callback function
  if (args.Length() > 0 && args[0]->IsFunction())
  {
    Handle<v8::Function> function = v8::Handle<v8::Function>::Cast(args[0]);
    Local<Value> argv[] = {
        Integer::New(env->isolate(), write_size_),
        Buffer::New(env, data[0], write_size_).ToLocalChecked()
    };

    if (argv[1].IsEmpty())
      argv[1] = Undefined(env->isolate());

    function->Call(function, arraysize(argv), argv);
  }*/

  // Return client initial data as buffer
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size_).ToLocalChecked());
}

void QTLSWrap::WriteHandshakeData(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (!args[0]->IsUint8Array())
  {
    env->ThrowTypeError("First argument must be a buffer");
    return;
  }
  const char *data = Buffer::Data(args[0]);
  size_t length = Buffer::Length(args[0]);

  int written = BIO_write(wrap->enc_in_, data, length);
  args.GetReturnValue().Set(written);
}

void QTLSWrap::ReadHandshakeData(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  int read = SSL_do_handshake(wrap->ssl_);

  int err;
  const char *error_str = nullptr;
  Local<Value> arg = wrap->GetSSLError(read, &err, &error_str);
  if (!arg.IsEmpty())
  {
    wrap->MakeCallback(env->onerror_string(), 1, &arg);
    delete[] error_str;
    return;
  }
  int pending = BIO_pending(wrap->enc_out_);
  char *data = new char[pending];
  size_t write_size_ = crypto::NodeBIO::FromBIO(wrap->enc_out_)->Read(data, pending);
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size_).ToLocalChecked());
}

void QTLSWrap::SetTransportParams(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (args.Length() < 1 || !args[0]->IsUint8Array())
  {
    return env->ThrowTypeError("Argument must be a buffer");
  }

  Local<Object> bufferObj = args[0]->ToObject();
  unsigned char *data = (unsigned char *)Buffer::Data(bufferObj);
  size_t length = Buffer::Length(bufferObj);

  //store data in variables to write in addtransportparamscb
  wrap->local_transport_parameters = new unsigned char[length];
  memcpy(wrap->local_transport_parameters, data, length);
  wrap->local_transport_parameters_length = length;
}

void QTLSWrap::GetTransportParams(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  // Return client initial data as buffer
  args.GetReturnValue().Set(Buffer::Copy(env, (char*)wrap->remote_transport_parameters, wrap->remote_transport_parameters_length).ToLocalChecked());
}

void QTLSWrap::ExportKeyingMaterial(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (!args[0]->IsUint8Array())
  {
    env->ThrowTypeError("First argument must be a buffer");
    return;
  }
  const char *label = Buffer::Data(args[0]);
  size_t labelsize = Buffer::Length(args[0]);

  size_t datasize = args[1]->NumberValue();
  unsigned char *data = new unsigned char[datasize];
  
  SSL_export_keying_material(wrap->ssl_, data, datasize, label, labelsize,reinterpret_cast<const uint8_t *>(""), 0, 1);
  args.GetReturnValue().Set(Buffer::Copy(env, (char*) data, datasize).ToLocalChecked());
}

void QTLSWrap::GetNegotiatedCipher(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  const SSL_CIPHER *c = SSL_get_current_cipher(wrap->ssl_);
  if (c == nullptr)
    return;

  const char *cipher_name = SSL_CIPHER_get_name(c);

  args.GetReturnValue().Set(OneByteString(args.GetIsolate(), cipher_name));
}

void QTLSWrap::SetVerifyMode(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (args.Length() < 2 || !args[0]->IsBoolean() || !args[1]->IsBoolean())
    return env->ThrowTypeError("Bad arguments, expected two booleans");

  if (wrap->ssl_ == nullptr)
    return env->ThrowTypeError("SetVerifyMode after destroyS,SL");

  int verify_mode;
  if (wrap->is_server())
  {
    bool request_cert = args[0]->IsTrue();
    if (!request_cert)
    {
      // Note reject_unauthorized ignored.
      verify_mode = SSL_VERIFY_NONE;
    }
    else
    {
      bool reject_unauthorized = args[1]->IsTrue();
      verify_mode = SSL_VERIFY_PEER;
      if (reject_unauthorized)
        verify_mode |= SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
    }
  }
  else
  {
    // Note request_cert and reject_unauthorized are ignored for clients.
    verify_mode = SSL_VERIFY_NONE;
  }

  // Always allow a connection. We'll reject in javascript.
  SSL_set_verify(wrap->ssl_, verify_mode, crypto::VerifyCallback);
}

} // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(qtls_wrap, node::QTLSWrap::Initialize)

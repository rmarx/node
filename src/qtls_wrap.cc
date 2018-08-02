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
#include <iostream> // TODO: remove if done debugging, needed for std::cerr
#include <algorithm> // needed for std::copy_n

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

void QTLSWrap::Log(const char* message){
  if( this->logging_enabled ){ 
    //fprintf(stderr, "------------------------------------------ \n");
    fprintf(stderr, "src/qtls_wrap.cc : ");   
    fprintf(stderr, message);
    fprintf(stderr, "\n");
    //fprintf(stderr, "------------------------------------------ \n");
  }
}

QTLSWrap::~QTLSWrap()
{
  // TODO: verify that this is all we need to do and we don't get memleaks! 
  this->sc_ = nullptr;
  this->enc_in_ = nullptr;
  this->enc_out_ = nullptr;
  if (this->local_transport_parameters != nullptr) {
    delete this->local_transport_parameters;
    this->local_transport_parameters = nullptr;
  }
  if (this->remote_transport_parameters != nullptr) {
    delete this->remote_transport_parameters;
    this->remote_transport_parameters = nullptr;
  }
}

// This is the first function called from JS-land and actually creates the QTLSWrap object 
void QTLSWrap::Wrap(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  if (args.Length() < 1 || !args[0]->IsObject())
  {
    return env->ThrowTypeError("first argument should be a SecureContext instance");
  }
  if (args.Length() < 2 || !args[1]->IsBoolean())
    return env->ThrowTypeError("second argument should be boolean (isServer)");
  if (args.Length() < 3 || !args[2]->IsBoolean())
    return env->ThrowTypeError("third argument should be boolean (shouldLog)");

  Local<Object> sc = args[0].As<Object>();
  Kind kind = args[1]->IsTrue() ? SSLWrap<QTLSWrap>::kServer : SSLWrap<QTLSWrap>::kClient;
  bool shouldLog = args[2]->IsTrue();

  if( shouldLog ){
    fprintf(stderr, "src/qtls_wrap.cc : Wrap called : ");
    fprintf(stderr, (kind == kServer) ? "server" : "client");
    fprintf(stderr, "\n");
  }

  QTLSWrap *res = new QTLSWrap(env, Unwrap<SecureContext>(sc), kind, shouldLog);

  args.GetReturnValue().Set(res->object());
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
  env->SetProtoMethod(t, "writeEarlyData", WriteEarlyData);
  env->SetProtoMethod(t, "readHandshakeData", ReadHandshakeData);
  env->SetProtoMethod(t, "readEarlyData", ReadEarlyData);
  env->SetProtoMethod(t, "readSSL", ReadSSL);
  env->SetProtoMethod(t, "enableSessionCallbacks", EnableSessionCallbacks);
  env->SetProtoMethod(t, "exportKeyingMaterial", ExportKeyingMaterial);
  env->SetProtoMethod(t, "exportEarlyKeyingMaterial", ExportEarlyKeyingMaterial);
  env->SetProtoMethod(t, "isEarlyDataAllowed", IsEarlyDataAllowed);
  env->SetProtoMethod(t, "getNegotiatedCipher", GetNegotiatedCipher);
  env->SetProtoMethod(t, "setServername", SetServername);

  SSLWrap<QTLSWrap>::AddMethods(env, t);

  env->set_qtls_wrap_constructor_function(t->GetFunction());

  target->Set(qtlsWrapString, t->GetFunction());
}

QTLSWrap::QTLSWrap(Environment *env, SecureContext *sc, Kind kind, bool enableLogging)
    : AsyncWrap(env,
                env->qtls_wrap_constructor_function()
                    ->NewInstance(env->context())
                    .ToLocalChecked(),
                AsyncWrap::PROVIDER_QTLSWRAP),
      SSLWrap<QTLSWrap>(env, QTLSWrap::PrepareContext(sc, kind), kind),
      sc_(sc),
      started_(false),
      local_transport_parameters(nullptr),
      local_transport_parameters_length(0),
      remote_transport_parameters(nullptr),
      remote_transport_parameters_length(0),
      server_has_setup_early_data(false),
      logging_enabled(enableLogging)
{
  node::Wrap(object(), this);
  MakeWeak(this);

  // sc comes from an Unwrap. Make sure it was assigned.
  CHECK_NE(sc, nullptr);

  InitSSL();
}

SecureContext* QTLSWrap::PrepareContext(SecureContext *sc, Kind kind)
{
  // 2nd value 0xffa5u is a quic-specific codepoint: https://tools.ietf.org/html/draft-ietf-quic-tls-13#section-8.2
  SSL_CTX_add_custom_ext(sc->ctx_, 0xffa5u,
                         SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS,
                         QTLSWrap::AddTransportParamsCallback, QTLSWrap::FreeTransportParamsCallback, nullptr,
                         QTLSWrap::ParseTransportParamsCallback, nullptr);

  if (kind == kServer) {
    /**
     * set to ffffffff according to QUIC to enable 0-RTT
     */

    std::cerr << "PrepareContext : setting max early data so we can use early data later on " << std::numeric_limits<uint32_t>::max() << std::endl;
    SSL_CTX_set_max_early_data(sc->ctx_, std::numeric_limits<uint32_t>::max()); 
  }



  // min version of QUIC (v1) is TLS 1.3
  SSL_CTX_set_min_proto_version(sc->ctx_, TLS1_3_VERSION);
  SSL_CTX_set_max_proto_version(sc->ctx_, TLS1_3_VERSION);
  
  // We've our own session callbacks
  SSL_CTX_sess_set_get_cb(sc->ctx_, SSLWrap<QTLSWrap>::GetSessionCallback);
  SSL_CTX_sess_set_new_cb(sc->ctx_, SSLWrap<QTLSWrap>::NewSessionCallback);

  SSL_CTX_set_mode(sc->ctx_, SSL_MODE_RELEASE_BUFFERS);

  // draft-13 via tatsuhiro openssl hack
  // TODO: remove in favor of real openssl implementation later
  SSL_CTX_set_mode(sc->ctx_, SSL_MODE_QUIC_HACK);

  // This makes OpenSSL client not send CCS after an initial ClientHello.
  // not 100% sure we need this, but seen in https://github.com/ngtcp2/ngtcp2/commit/5e8ee244a0ed0ed406cb761914d8aa767c77be73
  SSL_CTX_clear_options(sc->ctx_, SSL_OP_ENABLE_MIDDLEBOX_COMPAT);

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

  SSL_set_info_callback(ssl_, SSLInfoCallback);
  SSL_set_cert_cb(ssl_, SSLWrap<QTLSWrap>::SSLCertCallback, this);

  // draft-13 via tatsuhiro openssl hack
  // TODO: remove in favor of real openssl implementation later 
  // the main logic:
  // - All data we need to SEND TO our peer from TLS is gotten via the SSLMessageCallback
  //     -> this is called for each individual TLS message (e.g., ServerHello, Encrypted Extensions, Certificate, ...) 
  // - All data we RECEIVE FROM our peer that needs to be put into TLS is done using BIO_write
  //	-> processing of this data is then triggered by SSL_do_handshake
  // Keep in mind: data can be split over multiple packets. BIO_write needs to be called for all, which might or might not produce a new message callback
 	// -> use separate check to see if handshake has been successfully completed 
  // We do all this primarily to get KEY updates at the correct moments via the KeyCallback
	// this is used to update the encryption level. The KeyCallback is also automatically called after an SSL_do_handshake() is done with data in the BIO buffer that leads to key update
    // The order of MessageCallbacks and KeyCallbacks is also 100% well-defined (e.g., every message before a new KeyCallback belongs to the previous key/encryption level), no need to do anything else
    // e.g., order will always be : MessageCallback(ServerHello), KeyCallback(SERVER_HANDSHAKE), MessageCallback(EncryptedExtensions), MessageCallback(Certificate) ... 
    // and we will know ServerHello needs to be sent in an Initial encryption level, and EE etc. in Handshake encryption level 

  // Client						Server
  // (setup all stuff like transport parameters) (for 0-RTT: set SSL_SESSION)
  // if 0RTT: SSL_write_early_data
  // if 0RTT: EarlyDataToken + ClientHello: MessageCallback called
  // if 0RTT: SSL_KEY_CLIENT_EARLY_TRAFFIC: KeyCallback called
  // 
  // SSL_do_handshake()
  // if non-0RTT: ClientHello: MessageCallback called
  //						     => 
  //							BIO_write ClientHello 
  //							SSL_read_early_data (put in correct state/needed to enable 0-RTT if present)
  //							if 0RTT: SSL_KEY_CLIENT_EARLY_TRAFFIC: KeyCallback called
  //								-> in 0RTT, we don't need SSL_do_handshake(), ServerHello and the rest are auto-generated after SSL_read_early_data
  //							if not-0RTT:SSL_do_handshake()
  //							ServerHello: MessageCallback called
  //						    <=
  //							SSL_KEY_SERVER_HANDSHAKE_TRAFFIC: KeyCallback called
  //							if not 0RTT: SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC: KeyCallback called
  // BIO_write ServerHello
  // SSL_do_handshake()
  // SSL_KEY_SERVER_HANDSHAKE_TRAFFIC: KeyCallback called
  //							EncryptedExtensions: MessageCallback called
  // BIO_write EncryptedExtensions
  // SSL_do_handshake()
  // ~transport params are updated
  //							Certificate: MessageCallback called
  // BIO_write Certificate
  // SSL_do_handshake()
  //						    CertificateVerify: MessageCallback called
  // BIO_write CertificateVerify
  // SSL_do_handshake()
  //						    ServerFinished: MessageCallback called
  //							<=	
  // 							SSL_KEY_SERVER_APPLICATION_TRAFFIC: KeyCallback called
  // BIO_write ServerFinished
  // SSL_do_handshake()
  // SSL_KEY_SERVER_APPLICATION_TRAFFIC: KeyCallback Called
  // 
  // if 0RTT: EOED: MessageCallback called (4 bytes)
  // 						    => 
  // SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC: KeyCallback called
  //							if 0RTT: BIO_write EOED
  //							if 0RTT: SSL_do_handshake() 
  // 							if 0RTT: MessageCallback called
  // 							if 0RTT: SSL_KEY_CLIENT_HANDSHAKE_TRAFFIC: KeyCallback called
  // ClientFinished: MessageCallback called (also calls SSLInfoCallback with HANDSHAKE_DONE)
  //						    =>  
  // SSL_KEY_CLIENT_APPLICATION_TRAFFIC: KeyCallback called 
  //							BIO_write ClientFinished
  //							SSL_do_handshake()
  // 							SSL_KEY_CLIENT_APPLICATION_TRAFFIC: KeyCallback called 
  // 							NewSessionTicket:MessageCallback called (also calls SSLInfoCallback with HANDSHAKE_DONE)
  //							if not-0RTT: 2nd NewSessionTicket:MessageCallback called (AGAIN calls SSLInfoCallback with HANDSHAKE_DONE)
  //						    <=	
  // BIO_write NewSessionTicket
  // SSL_do_handshake()
  // SSL_read_ex to get SessionTicket (not consumed by SSL_do_handshake)
  // SSLInfoCallback called (HANDSHAKE_DONE)
  // if not-0RTT: SSL_read_ex to get 2nd SessionTicket (not consumed by SSL_do_handshake)
  // SSLInfoCallback called (HANDSHAKE_DONE)

  // BIG TODO: HANDSHAKE_DONE callback is called multiple times now, that probably shouldn't happen / be caught better (application now takes this into account, but only in 1 function and not very well)


  // Possible API:
  // GetClientInitial(client_transport_params) ((write_early_data) + do_handshake) -> leads to OnNewHandshakeData(CRYPTO) callback 
  // ProcessReceivedHandshakeData(CRYPTO) (BIO + (read_early_data) + do_handshake + read_ssl_ex) -> leads to OnNewHandshakeData(CRYPTO) callback 

  SSL_set_key_callback(ssl_, SSLKeyCallback, NULL); // last argument is used to pass around app state, but we use SSL_get_app_data to pass around our SSL* object 
  SSL_set_msg_callback(ssl_, SSLMessageCallback);
  //SSL_set_msg_callback_arg(ssl_, this); // ngtcp2 uses this to pass context, but here we just get the SSL* object directly bye using SSL_get_app_data
}

void QTLSWrap::EnableSessionCallbacks(
    const FunctionCallbackInfo<Value>& args) {
  QTLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  if (wrap->ssl_ == nullptr) {
    return wrap->env()->ThrowTypeError("EnableSessionCallbacks after destroySSL");
  }
  wrap->enable_session_callbacks();
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

  unsigned char* temp = new unsigned char[qtlsWrap->local_transport_parameters_length];
  memcpy(temp, qtlsWrap->local_transport_parameters, qtlsWrap->local_transport_parameters_length);
  *out = temp;
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
  QTLSWrap *wrap = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));


  if (where & SSL_CB_HANDSHAKE_START)
  {
  	wrap->Log("SSLInfoCallback : SSL_CB_HANDSHAKE_START");
  }

  if (where & SSL_CB_HANDSHAKE_DONE)
  {
  	wrap->Log("SSLInfoCallback : SSL_CB_HANDSHAKE_DONE");

    Environment *env = wrap->env();
    Local<Object> object = wrap->object();

    Local<Value> callback = object->Get(env->onhandshakedone_string());
    if (callback->IsFunction()) {
      wrap->MakeCallback(callback.As<Function>(), 0, nullptr);
    }
  }
}

// draft-13 via tatsuhiro openssl 
int QTLSWrap::SSLKeyCallback(SSL *ssl_, int name,
                                     const unsigned char *secret,
                                     size_t secretlen, const unsigned char *key,
                                     size_t keylen, const unsigned char *iv,
                                     size_t ivlen, void *arg){
  SSL *ssl = const_cast<SSL *>(ssl_);
  QTLSWrap *wrap = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));
  Environment *env = wrap->env();

  wrap->Log("SSLKeyCallback");


  /* 
  // Used this to check in JS-land if the values are correctly send using the complex casts below
  // both for-loops should print the same, but I was paranoid
  for( int i = 0; i < secretlen; ++i )
	fprintf(stderr, "%u ", secret[i] );
  fprintf(stderr, "\n");
  for( int i = 0; i < secretlen; ++i ){
        short c = (short) *(secret + i);
	fprintf(stderr, "%i ", c);
  }
  fprintf(stderr, "\n");
  */


    // TODO: see if these are actually the best ways to pass data back to JS-land
    // current code is based on node_crypto.cc::NewSessionCallback 
    // for JS-land interface, see lib/qtls_wrap.js:onnewkey
    Local<Value> argv[] = {
        Integer::New(env->isolate(), name),
        Buffer::Copy(env, const_cast<char*>(reinterpret_cast<const char*>(secret)), secretlen).ToLocalChecked(),
        Integer::New(env->isolate(), (int) secretlen),
        Buffer::Copy(env, const_cast<char*>(reinterpret_cast<const char*>(key)), keylen).ToLocalChecked(),
        Integer::New(env->isolate(), (int) keylen),
        Buffer::Copy(env, const_cast<char*>(reinterpret_cast<const char*>(iv)), ivlen).ToLocalChecked(),
        Integer::New(env->isolate(), (int) ivlen),
        Integer::New(env->isolate(), 666) // "arg" is currently not used, pass a generic integer (in JS-land, it's all JS objects anyway, so can change this later trivially here 
    };

    wrap->MakeCallback(env->onnewkey_string(), arraysize(argv), argv); 

  return 1;
}

void QTLSWrap::SSLMessageCallback(	int write_p, 
					int version, 
					int content_type, 
					const void *buf, 
					size_t len, 
					SSL *ssl,  
					void *arg) {

  // https://www.openssl.org/docs/man1.1.0/ssl/SSL_set_msg_callback.html
  // write_p : 0 if has been received, 1 if has been sent
  // version: 772 (= 0x304) for TLS1_3_VERSION, see openssl: ./include/openssl/tls1.h
	// -> version: 0 (= 0x00) : this signifies the SSL record header, not data itself (TODO: though tatsuhiro just takes this data as well, apparently...)
  // content_type: change_cipher_spec(20), alert(21), handshake(22); but never application_data(23) because the callback will only be called for protocol messages
	// see include/openssl/ssl3.h for definitions 
	// # define SSL3_RT_HEADER                  0x100 -> = 256
	// # define SSL3_RT_INNER_CONTENT_TYPE      0x101 -> = 257
	// # define SSL3_RT_CHANGE_CIPHER_SPEC      20
	// # define SSL3_RT_ALERT                   21
	// # define SSL3_RT_HANDSHAKE               22

	/*
	// https://boringssl.googlesource.com/boringssl/+/59015c365b53a855513aaf5f9ff4597df9157ac0%5E!/
	For each record header, |cb| is called with |version| = 0 and |content_type|
	+ * = |SSL3_RT_HEADER|. The |len| bytes from |buf| contain the header. Note that
	+ * this does not include the record body. If the record is sealed, the length
	+ * in the header is the length of the ciphertext.
	+ *
	+ * For each handshake message, ChangeCipherSpec, and alert, |version| is the
	+ * protocol version and |content_type| is the corresponding record type. The
	+ * |len| bytes from |buf| contain the handshake message, one-byte
	+ * ChangeCipherSpec body, and two-byte alert, respectively.
	*/

  // NOTE: we expect all messages to be complete. I.e., there is no fragmentation and we can be sure that this function is called just once in every stage of the handshake
  // this means we can just pass this message on to QUIC in full, which can then decide to fragment into crypto frames/packets as needed 
  // we can keep feeding received CRYPTO data into OpenSSL, being sure this callback will only be called when the received message is complete (
  int rv;

  std::cerr << "----------------------------------------" << std::endl << 
	    "SSLMessageCallback: write_p=" << write_p << " version=" << version
            << " content_type=" << content_type << " len=" << len << std::endl
	    << "----------------------------------------" << std::endl;

	// code from https://github.com/ngtcp2/ngtcp2/commit/19cce627eed659ce47816e201f93abd26d7ac365
/*
  if (!write_p || content_type != SSL3_RT_HANDSHAKE) {
    return;
  }

  auto c = static_cast<Client *>(arg);

  rv = c->write_client_handshake(reinterpret_cast<const uint8_t *>(buf), len);
*/

  if( write_p && content_type == SSL3_RT_HANDSHAKE ){
    
    QTLSWrap *qtlsWrap = static_cast<QTLSWrap *>(SSL_get_app_data(ssl));

    // TODO: FIXME: REMOVE! very ugly, just for quick testing! 
    //if( qtlsWrap->kind_ != kServer ){
	//qtlsWrap->serverHandshakeDataDEBUG = std::vector<char>();
   //}

    //if( qtlsWrap->kind_ == kServer ){
	//qtlsWrap->serverHandshakeDataDEBUG.insert(qtlsWrap->serverHandshakeDataDEBUG.end(), len, reinterpret_cast<char*>(const_cast<void*>(buf)));
	char* buf2 = reinterpret_cast<char*>(const_cast<void*>(buf));
	//qtlsWrap->serverHandshakeDataDEBUG.insert(qtlsWrap->serverHandshakeDataDEBUG.end(), buf2[0], buf2[qtlsWrap->serverHandshakeDataDEBUG.size()] );

	std::copy_n(buf2, len, std::back_inserter(qtlsWrap->serverHandshakeDataDEBUG));

        std::cerr << "msg_cb : appended handshakedata to vector " << len << " -> " << qtlsWrap->serverHandshakeDataDEBUG.size() << std::endl;

	  for( int i = 0; i < len; ++i )
		fprintf(stderr, "%u ", reinterpret_cast<unsigned char*>(const_cast<void*>(buf))[i] );
	  fprintf(stderr, "\n");
	  fprintf(stderr, "\n");
	  fprintf(stderr, "\n");
    //}
    //else{
    //	qtlsWrap->handshakeDataDEBUG = reinterpret_cast<char*>(const_cast<void*>(buf));
    //	qtlsWrap->handshakeLengthDEBUG = len;
    //}
  }
}

void QTLSWrap::GetClientInitial(const FunctionCallbackInfo<Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  CHECK(wrap->is_client());

  wrap->Log("GetClientInitial");


  // First, see if we're resuming with SSL_SESSION_get_max_early_data, which will only return > 0 if we're starting connection from a NewSessionTicket with early data allowances set
  // Note: right now, this function is only supposed to be called at the Client!!
  // On the server, it will still return 0 before ClientFinished has been received, but after that it will return > 0, even on the "first" non-resumed connection
  // So if you ever refactor this, take that into account
  // When not resuming, SSL_get_session might not return correctly, so check for that first (TODO: ngtcp2 does NOT check for this, should we?)
  if( SSL_get_session(wrap->ssl_) && SSL_SESSION_get_max_early_data(SSL_get_session(wrap->ssl_)) ){

    wrap->Log("GetClientInitial:SSL_write_early_data (should only be done once and only when resuming connection)");

  	// we need to call ssl_write_early_data when we're doing resumption or we won't get 0RTT keys or EOED generation (+ this must be called before first SSL_do_handshake)
  	// we don't actually want to send anything of course (we do that in Protected0RTT packet in the QUIC layer), so we just write an empty string here
	// code adapted from ngtcp2::Client::tls_handshake
    size_t nwrite;
    int rv = SSL_write_early_data(wrap->ssl_, "", 0, &nwrite); 
	if (rv == 0) {
		int err;
		const char *error_str = nullptr;
		Local<Value> arg = wrap->GetSSLError(rv, &err, &error_str);
		if (!arg.IsEmpty())
		{
    		wrap->Log("GetClientInitial:SSL_write_early_data:ERROR occured");
			wrap->MakeCallback(env->onerror_string(), 1, &arg);
			delete[] error_str;
			return;
		}	
	}
  }

  // next call will return -1 because OpenSSL can't complete the handshake when it is just starting
  int read = SSL_do_handshake(wrap->ssl_);

  std::cerr << "GetClientInitial: SSL_do_handshake returned " << read << std::endl;

  int err;
  const char *error_str = nullptr;
  Local<Value> arg = wrap->GetSSLError(read, &err, &error_str);
  if (!arg.IsEmpty())
  {
    wrap->MakeCallback(env->onerror_string(), 1, &arg);
    delete[] error_str;
    return;
  }

  #if DRAFT12
  int pending = BIO_pending(wrap->enc_out_);
  char *data = new char[pending];
  size_t write_size_ = crypto::NodeBIO::FromBIO(wrap->enc_out_)->Read(data, pending);
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size_).ToLocalChecked());
  #endif
 
  //std::cerr << "GetClientInitial: bubbling up handshakedata " << wrap->handshakeLengthDEBUG << std::endl;
  //args.GetReturnValue().Set(Buffer::Copy(env, wrap->handshakeDataDEBUG, wrap->handshakeLengthDEBUG).ToLocalChecked());

  std::cerr << "GetClientInitial: bubbling up handshakedata " << wrap->handshakeLengthDEBUG << ", PENDING: " << wrap->serverHandshakeDataDEBUG.size() << std::endl;  
  size_t write_size = wrap->serverHandshakeDataDEBUG.size();
  char* data = new char[write_size];
  std::copy(wrap->serverHandshakeDataDEBUG.begin(), wrap->serverHandshakeDataDEBUG.end(), data);

  wrap->serverHandshakeDataDEBUG = std::vector<char>();
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size).ToLocalChecked());
}

void QTLSWrap::WriteHandshakeData(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  wrap->Log("WriteHandshakeData");

  if (!args[0]->IsUint8Array())
  {
    env->ThrowTypeError("First argument must be a buffer");
    return;
  }
  const char *data = Buffer::Data(args[0]);
  size_t length = Buffer::Length(args[0]);

  // note: this doesn't do anything by itself, just puts data in a buffer
  // top-level apps then call ReadHandshakeData (which calls SSL_do_handshake) immediately afterwards to get new TLS messages generated based on what we've just written 
  int written = BIO_write(wrap->enc_in_, data, length);

  if( wrap->kind_ == kServer && !wrap->server_has_setup_early_data ){
    wrap->server_has_setup_early_data = true;

    wrap->Log("WriteHandshakeData:SSL_read_early_data (should only be done on the Server and only once right after writing ClientHello to OpenSSL)");

    // According to the documentation (https://www.openssl.org/docs/man1.1.1/man3/SSL_read_early_data.html), 
    // if we use SSL_CTX_set_max_early_data (which is necessary to allow for 0-RTT data and we do that in SetupContext above), we also need to call SSL_read_early_data
    // (if we don't do this, for some reason, the client won't send EOED when actually resuming a connection)
    // This is somewhat counter-intuitive, since we don't use TLS1.3's mechanism for actually sending the early-data, but rather use Protected0RTT QUIC packets instead
    // However, this triggers a a state-change in OpenSSL, allowing us to get the necessary 0-RTT keys 
    // This is why we don't actually bubble up the "read" early data, since there shouldn't be any 
    // Connection 1 (no resumption): we trigger creation of NewSessionTicket with early data allowed 
    // Connection 2 (resumption): we trigger generation of 0-RTT keys 
    // this code was adapted from ngtcp2's server.cc:read_tls
    std::array<uint8_t, 8> buf;
    size_t nread;

    // Note: This will trigger immediate calls to MessageCallback and KeyCallback if the data is sufficient (kind of takes the role of SSL_do_handshake at the start)
    // i.e., right after this call, we can be in a different application state with new keys than before, without even having to call SSL_do_handshake
    // we can (and do) still call SSL_do_handshake below, it just won't have any effect in this stage of the setup 

    // TODO: FIXME: shouldn't this be done in a loop? ngtcp2 doesn't, but if it gets SSL_WANT_READ or WANT_WRITE, it doesn't do SSL_do_handshake afterwards, we do
    // ngtcp2 also only does a buffer of length 8, no idea why 
    // current code seems to work fine, but possibly because we're not sending very large packets yet etc. 
    int rv = SSL_read_early_data(wrap->ssl_, buf.data(), buf.size(), &nread);

	  switch (rv) {
	    case SSL_READ_EARLY_DATA_ERROR: {
          int err;
		  const char *error_str = nullptr;
		  Local<Value> arg = wrap->GetSSLError(rv, &err, &error_str);
		  if (!arg.IsEmpty())
		  {
    		wrap->Log("WriteHandshakeData:SSL_read_early_data:ERROR occured");
			wrap->MakeCallback(env->onerror_string(), 1, &arg);
			delete[] error_str;
			return;
		  }
	      break;
	    }
	    case SSL_READ_EARLY_DATA_SUCCESS:
	      // Reading early (0-RTT) data in TLS stream is a protocol violation, should be sent separately using Protected0RTT packet
	      if (nread > 0) {
    		wrap->Log("WriteHandshakeData:SSL_read_early_data:ERROR occured: actual early data received at TLS level!");
  			const char* message = "OpenSSL received TLS-level early data, which isn't allowed in QUIC. Use a Protected0RTT packet instead!\0";
		    Local<Object> messageBuffer = Buffer::Copy(env, message, strlen(message) + 1).ToLocalChecked();
			Local<Value> arg[] = {messageBuffer};
			wrap->MakeCallback(env->onerror_string(), 1, arg );
            return;
	      }
	      break;
	    //case SSL_READ_EARLY_DATA_FINISH:
	    //  std::cerr << "SSL_READ_EARLY_DATA_FINISH" << std::endl;
	    //  break;
	  }    
  } // end server_has_setup_early_data


  args.GetReturnValue().Set(written);
}

void QTLSWrap::WriteEarlyData(const v8::FunctionCallbackInfo<v8::Value> &args)
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

  size_t written;
  // DRAFT-13 : shouldn't be a problem that we're calling this. First call is with empty string, which is exactly what ngtcp2 also does (see ngtcp2/client.cc:tls_handshake)
  int status = SSL_write_early_data(wrap->ssl_, data, length, &written);
  args.GetReturnValue().Set(Integer::New(env->isolate(), status));
}

void QTLSWrap::ReadHandshakeData(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  wrap->Log("ReadHandshakeData");

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

  #if DRAFT12
  int pending = BIO_pending(wrap->enc_out_);
  char *data = new char[pending];
  size_t write_size_ = crypto::NodeBIO::FromBIO(wrap->enc_out_)->Read(data, pending);
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size_).ToLocalChecked());
  #endif


  size_t write_size = wrap->serverHandshakeDataDEBUG.size();
  char* data = new char[write_size];
  std::copy(wrap->serverHandshakeDataDEBUG.begin(), wrap->serverHandshakeDataDEBUG.end(), data);



  // SSL_do_handshake doesn't always process all crypto data we put into SSL
  // for example, NewSessionTickets aren't regarded as part of the handshake. We write them with BIO_write, but they are not consumed by SSL_do_handshake
  // so, we need to trigger this consumption with SSL_read_ex (if we don't, we cannot resume + NewSessionCallback isn't called at client side (as the SSL buffer is not completely empty))
  // if there is nothing left in the buffer (e.g., SSL_do_handshake processed everything) or it's waiting for extra handshake data, SSL_read_ex will be a no-op
  // we also call this at the server side, because OpenSSL might have generated an Alert that we want to catch
  // TODO: TLS alerts aren't notified via the Crypto stream, so maybe needs additional handling here? 
  // the following code was adapted from ngtcp2::Client::read_tls (server's version is almost identical)

  std::array<uint8_t, 4096> buf;
  size_t nread;

  for (;;) { // only needed at client 

    auto rv = SSL_read_ex(wrap->ssl_, buf.data(), buf.size(), &nread);

    if (rv == 1) {
  	  wrap->Log("ReadHandshakeData:SSL_read_ex succeeded");

      if( wrap->kind_ == kServer ){ // server shouldn't be getting extraneous SSL data outside handshake 
  		wrap->Log("ReadHandshakeData:SSL_read_ex:ERROR occured: server isn't supposed to get data outside of the handshake flow, only client!");
		const char* message = "ReadHandshakeData:SSL_read_ex:ERROR occured: server isn't supposed to get data outside of the handshake flow, only client!\0";
	    Local<Object> messageBuffer = Buffer::Copy(env, message, strlen(message) + 1).ToLocalChecked();
		Local<Value> arg[] = {messageBuffer};
		wrap->MakeCallback(env->onerror_string(), 1, arg );
        return;
      }
      else // at client, these are our NewSessionTicket(s), keep reading until we're done 
	   	continue;
    }
    else{ // error 
		int err;
		const char *error_str = nullptr;
		Local<Value> arg = wrap->GetSSLError(rv, &err, &error_str);
		if (!arg.IsEmpty()) 
		{
			wrap->MakeCallback(env->onerror_string(), 1, &arg);
			delete[] error_str;
			return;
		}
		else
		    break; // SSL_want_read or want_write : need to get another packet to resolve that, break out of this loop 
	}
  }


  wrap->serverHandshakeDataDEBUG = std::vector<char>(); // prepare for next time 
  args.GetReturnValue().Set(Buffer::Copy(env, data, write_size).ToLocalChecked());
}

void QTLSWrap::ReadEarlyData(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  size_t read;
  int status;
  int totalRead = 0;
  int buffSize = 4096;
  char* data = new char[buffSize];
  std::vector<char*> dataVector;
  for (;;) {
    status = SSL_read_early_data(wrap->ssl_, data, buffSize, &read);

    if (status <= 0)
      break;
    dataVector.push_back(data);
    totalRead += read;
  }
  char* allData = new char[totalRead];
  for(int i = 0; i < totalRead; i++) {
    char* dp = dataVector.at(i / buffSize);
    allData[i] = dp[i % buffSize];
  }
  
  args.GetReturnValue().Set(Buffer::Copy(env, allData, totalRead).ToLocalChecked());
}

void QTLSWrap::ReadSSL(const v8::FunctionCallbackInfo<v8::Value> &args)
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  size_t read;
  int status;
  int totalRead = 0;
  int buffSize = 4096;
  char* data = new char[buffSize];
  std::vector<char*> dataVector;
  for (;;) {
    status = SSL_read_ex(wrap->ssl_, data, buffSize, &read);

    if (status <= 0)
      break;
    dataVector.push_back(data);
    totalRead += read;
  }
  char* allData = new char[totalRead];
  for(int i = 0; i < totalRead; i++) {
    char* dp = dataVector.at(i / buffSize);
    allData[i] = dp[i % buffSize];
  }

  std::cerr << "QTLSWrap::ReadSSL : reading " << totalRead << std::endl;  

  args.GetReturnValue().Set(Buffer::Copy(env, allData, totalRead).ToLocalChecked());
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

void QTLSWrap::ExportEarlyKeyingMaterial(const v8::FunctionCallbackInfo<v8::Value> &args)
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
  
  SSL_export_keying_material_early(wrap->ssl_, data, datasize, label, labelsize,reinterpret_cast<const uint8_t *>(""), 0);
  args.GetReturnValue().Set(Buffer::Copy(env, (char*) data, datasize).ToLocalChecked());
}
void QTLSWrap::IsEarlyDataAllowed(const FunctionCallbackInfo<Value>& args) 
{
  Environment *env = Environment::GetCurrent(args);

  QTLSWrap *wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());
  if (!SSL_get_session(wrap->ssl_)) {
    args.GetReturnValue().Set(false);
    return;
  }
  // Note: Without resumption, will return false at server before ClientFinished received, even if we've set max_early_data on the CTX first
  // With resumption, always returns true both on client and server
  bool isEarlyDataAllowed = SSL_SESSION_get_max_early_data(SSL_get_session(wrap->ssl_));
  args.GetReturnValue().Set(isEarlyDataAllowed);
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

void QTLSWrap::SetServername(const FunctionCallbackInfo<Value>& args) {
  Environment* env = Environment::GetCurrent(args);

  QTLSWrap* wrap;
  ASSIGN_OR_RETURN_UNWRAP(&wrap, args.Holder());

  if (args.Length() < 1 || !args[0]->IsString())
    return env->ThrowTypeError("First argument should be a string");

  if (!wrap->is_client())
    return;

  CHECK_NE(wrap->ssl_, nullptr);

  node::Utf8Value servername(env->isolate(), args[0].As<String>());
  SSL_set_tlsext_host_name(wrap->ssl_, *servername);
}

} // namespace node

NODE_MODULE_CONTEXT_AWARE_BUILTIN(qtls_wrap, node::QTLSWrap::Initialize)

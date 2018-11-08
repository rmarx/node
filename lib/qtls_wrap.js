'use strict';

require('internal/util').assertCrypto();

const EventEmitter = require('events');
const assert = require('assert');
const crypto = require('crypto');
const util = require('util');
const { Buffer } = require('buffer');
const tls = require('tls'); // securecontext
const debug = util.debuglog('qtls');
const qtls_wrap = process.binding('qtls_wrap');
const errors = require('internal/errors');

const internalUtil = require('internal/util');
const binding = process.binding('crypto');

QuicTLS.prototype.logQtlsWrap = function(message, ...args){
    if( this.shouldLog ){
        if( this.logger ){
            let argString = "";
            for( let arg of args ){
                argString += "" + JSON.stringify(arg) + ",";
            }
            if( argString.length > 0 )
                argString = " -- " + argString;
                
            this.logger.info("NODE: lib/qtls_wrap.js: #" + this.logID + " : " + message + argString );
        }
        else{
	        console.log("NODE: lib/qtls_wrap.js: #" + this.logID + " : " + message, (args && args.length > 0 ) ? args : "" );
	    }
	}
}

function QuicTLS(isServer, options) {
    if (options === undefined)
        this._tlsOptions = {};
    else
        this._tlsOptions = options;
    this._secureEstablished = false;
    this._securePending = false;
    this._newSessionPending = false;
    this._controlReleased = false;
    this._SNICallback = null;
    this.servername = null;
    this.alpnProtocol = null;
    this.authorized = false;
    this.authorizationError = null;


    this.logID = Math.round(Math.random() * 10000); // if there are multiple sockets, we want to differentiate
    this.shouldLog = (this._tlsOptions.logLevel == "debug" || this._tlsOptions.logLevel == "trace" || this._tlsOptions.logLevel == "info");
    this.logger = this._tlsOptions.logger ? this._tlsOptions.logger : undefined;
    this.logQtlsWrap("Ctor called :", {isServer: isServer}, options );


    this._handle = this._callWrap(isServer, this);
    this._handle.owner = this;

    this.ssl = this._handle;

    this._init(isServer);
    EventEmitter.call(this);
}
util.inherits(QuicTLS, EventEmitter);

exports.QuicTLS = QuicTLS;


QuicTLS.prototype._callWrap = function (isServer, handle) {
    var options = this._tlsOptions;
    
    //this.logQtlsWrap("_callWrap : tlsOptions: ", options );
    // Wrap socket's handle
    const context = options.secureContext ||
        options.credentials ||
        tls.createSecureContext(options);

    //this.logQtlsWrap("_callWrap : tlsOptions: ", context );
    //console.log( context );
    

    const res = qtls_wrap.wrap(context.context,
        !!isServer, !!this.shouldLog);
    res._parent = handle;
    res._secureContext = context;
    return res;
};

QuicTLS.prototype.setTransportParameters = function(buffer) {
    this.logQtlsWrap("setTransportParameters :", buffer );
    this._handle.setTransportParams(buffer);
};

QuicTLS.prototype.getTransportParameters = function() {
    let result = this._handle.getTransportParams();
    this.logQtlsWrap("getTransportParameters :", result );
    return result;
};

QuicTLS.prototype.getClientInitial = function() {
    this.logQtlsWrap("START getClientInitial" );
    let result = this._handle.getClientInitial();
    this.logQtlsWrap("DONE getClientInitial :", result );
    return result;
};

QuicTLS.prototype.writeHandshakeData = function(buffer) {
    this.logQtlsWrap("START writeHandshakeData" );
    let result = this._handle.writeHandshakeData(buffer);
    this.logQtlsWrap("DONE writeHandshakeData :", result );
    return result;
};

QuicTLS.prototype.writeEarlyData = function(buffer) {
    //this.logQtlsWrap("START writeEarlyData" );
    //let result = this._handle.writeEarlyData(buffer);

    let result = "";
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("DONE writeEarlyData : denied, is now done directly in qtls, remove this binding from NodeJS country!" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );

    return result;
};

QuicTLS.prototype.readHandshakeData = function() {
    //this.logQtlsWrap("START readHandshakeData" );
    //let result = this._handle.readHandshakeData();
    //this.logQtlsWrap("DONE readHandshakeData :", result );
    
    let result = "";
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("readHandshakeData : denied, is now done directly in qtls, remove this binding from NodeJS country!");
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    return result;
};

QuicTLS.prototype.readEarlyData = function() {
    //let result = this._handle.readEarlyData();
    //this.logQtlsWrap("readEarlyData :", result );
    let result = "";
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("READEARLYDATA : denied, should NOT be necessary! TODO DEBUG: check if this is actually the case! Think ngtpc2 only does this to check if early_data is really not used, because that's not allowed in QUIC, not because it's necessary for openSSL");
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    return result;
};

QuicTLS.prototype.readSSL = function(buffer) {
    //this.logQtlsWrap("START readSSL" );
    //let result = this._handle.readSSL();
    //this.logQtlsWrap("DONE readSSL :", result );
    let result = "";
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("readSSL : denied, is now done directly in qtls, remove this binding from NodeJS country!");
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    this.logQtlsWrap("@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@@" );
    return result;
};

QuicTLS.prototype.getNegotiatedCipher = function() {
    let result = this._handle.getNegotiatedCipher();
    this.logQtlsWrap("getNegotiatedCipher :", result );
    return result;
};

QuicTLS.prototype.exportKeyingMaterial = function(labelBuffer, hashsize) {
    this.logQtlsWrap("exportKeyingMaterial :", hashsize );
    return this._handle.exportKeyingMaterial(labelBuffer, hashsize);
};

QuicTLS.prototype.exportEarlyKeyingMaterial = function(labelBuffer, hashsize) {
    this.logQtlsWrap("exportEarlyKeyingMaterial :", hashsize );
    return this._handle.exportEarlyKeyingMaterial(labelBuffer, hashsize);
};

QuicTLS.prototype.setSession = function(session) {
  this.logQtlsWrap("setSession :", session );
  if (typeof session === 'string')
    session = Buffer.from(session, 'latin1');
  this._handle.setSession(session);
};

QuicTLS.prototype.getSession = function() {
  if (this._handle) {
    let result = this._handle.getSession();
    this.logQtlsWrap("getSession :", result );
    return result;
  }

  return null;
};

QuicTLS.prototype.isEarlyDataAllowed = function() {
  if (this._handle) {
    let result = this._handle.isEarlyDataAllowed();
    this.logQtlsWrap("isEarlyDataAllowed :", result );
    return result;
  }

  return null;
};

QuicTLS.prototype.isSessionReused = function() {
  if (this._handle) {
    let result = this._handle.isSessionReused();
    this.logQtlsWrap("isSessionReused :", result );
    return result;
  }

  return null;
};

function onerror(e) {
    //debug(e);
    this.owner.logQtlsWrap("onerror :", e );
    this.owner.emit("error", e);
}

function onhandshakedone() {
    //debug("hs done");
    this.owner.logQtlsWrap("onhandshakedone fired");
    this.owner.logQtlsWrap("onhandshakedone : ALPN selected is : ", this.owner._handle.getALPNNegotiatedProtocol());
    this.owner.emit("handshakedone");
}

function onnewsession() {
    //debug("on new session");
    this.owner.logQtlsWrap("onnewsession fired");
    this.owner.emit("newsession");
}

function onnewkey(keytype, secret, secretLength, key, keyLength, iv, ivLength, arg){
    //debug("on new key");

    this.owner.logQtlsWrap("onnewkey fired");
    
    this.owner.emit("onnewkey", keytype, secret, secretLength, key, keyLength, iv, ivLength, arg);
}

function onnewtlsmessage( message, length ){
	this.owner.logQtlsWrap("on new TLS message fired");

	//this.owner.logQtlsWrap("onnewtlsmessage fired", length, message);

    this.owner.emit("onnewtlsmessage", message, length); 
}

QuicTLS.prototype._init = function (isServer) {
    this.logQtlsWrap("_init" );

    var options = this._tlsOptions;
    var ssl = this._handle;

    ssl.writeQueueSize = 1;

    this.server = options.server;

    // For clients, we will always have either a given ca list or be using
    // default one
    const requestCert = !!options.requestCert || !isServer;
    const rejectUnauthorized = !!options.rejectUnauthorized;

    this._requestCert = requestCert;
    this._rejectUnauthorized = rejectUnauthorized;
    if (requestCert || rejectUnauthorized){
    	this.logQtlsWrap("_init : sslVerifyMode ", {requestCert: requestCert, rejectUnauthorized: rejectUnauthorized} );
        ssl.setVerifyMode(requestCert, rejectUnauthorized);
    }

    ssl.onerror = onerror;
    ssl.onhandshakedone = onhandshakedone;
    ssl.onnewsession = onnewsession;
    ssl.onnewkey = onnewkey;
    ssl.onnewtlsmessage = onnewtlsmessage; 

    ssl.enableSessionCallbacks();
    if (isServer) {
        if (this.server) {
            if (this.server.listenerCount('OCSPRequest') > 0){
    		this.logQtlsWrap("_init : enabling cert OCSP callback" );
                ssl.enableCertCb();
	    }
        }
    } else {
        if (options.session){
    	    this.logQtlsWrap("_init : resumption, loading session from options", options.session );
            ssl.setSession(options.session);
	}

        if (options.host === '127.0.0.1') {
            ssl.setServername('localhost');
        } else {
            ssl.setServername(options.host);
        }
    }

    // If custom SNICallback was given, or if
    // there're SNI contexts to perform match against -
    // set `.onsniselect` callback.
    if (process.features.tls_sni &&
        isServer &&
        options.SNICallback &&
        options.server &&
        (options.SNICallback !== SNICallback ||
            options.server._contexts.length)) {
        assert(typeof options.SNICallback === 'function');
    	this.logQtlsWrap("_init : setting custom SNICallback, passed from options" );
        this._SNICallback = options.SNICallback;
        ssl.enableCertCb();
    }

    if (options.alpnProtocols) {
        // keep reference in secureContext not to be GC-ed
        var buff = convertProtocols(options.alpnProtocols);
        ssl._secureContext.alpnBuffer = buff;
        ssl.setALPNProtocols(ssl._secureContext.alpnBuffer);

    	this.logQtlsWrap("_init : setting ALPN : ", options.alpnProtocols, ssl._secureContext.alpnBuffer );
    }
};


exports.DEFAULT_CIPHERS = process.binding('constants').crypto.defaultCipherList;
exports.getCiphers = internalUtil.cachedResult(
    () => internalUtil.filterDuplicateStrings(binding.getSSLCiphers(), true)
);

// Convert protocols array into valid OpenSSL protocols list
// ("\x06spdy/2\x08http/1.1\x08http/1.0")
function convertProtocols(protocols) {
    const lens = new Array(protocols.length);
    const buff = Buffer.allocUnsafe(protocols.reduce((p, c, i) => {
        var len = Buffer.byteLength(c);
        lens[i] = len;
        return p + 1 + len;
    }, 0));

    var offset = 0;
    for (var i = 0, c = protocols.length; i < c; i++) {
        buff[offset++] = lens[i];
        buff.write(protocols[i], offset);
        offset += lens[i];
    }

    return buff;
}
exports.convertALPNProtocols = function (protocols, out) {
    // If protocols is Array - translate it into buffer
    if (Array.isArray(protocols)) {
        out.ALPNProtocols = convertProtocols(protocols);
    } else if (isUint8Array(protocols)) {
        // Copy new buffer not to be modified by user.
        out.ALPNProtocols = Buffer.from(protocols);
    }
};

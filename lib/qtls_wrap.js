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
    // Wrap socket's handle
    const context = options.secureContext ||
        options.credentials ||
        tls.createSecureContext(options);
    const res = qtls_wrap.wrap(context.context,
        !!isServer);
    res._parent = handle;
    res._secureContext = context;
    return res;
};

QuicTLS.prototype.setTransportParameters = function(buffer) {
    this._handle.setTransportParams(buffer);
};

QuicTLS.prototype.getTransportParameters = function() {
    return this._handle.getTransportParams();
};

QuicTLS.prototype.getClientInitial = function() {
    return this._handle.getClientInitial();
};

QuicTLS.prototype.writeHandshakeData = function(buffer) {
    return this._handle.writeHandshakeData(buffer);
};

QuicTLS.prototype.writeEarlyData = function(buffer) {
    return this._handle.writeEarlyData(buffer);
};

QuicTLS.prototype.readHandshakeData = function() {
    return this._handle.readHandshakeData();
};

QuicTLS.prototype.readEarlyData = function() {
    return this._handle.readEarlyData();
};

QuicTLS.prototype.readSSL = function(buffer) {
    return this._handle.readSSL();
};

QuicTLS.prototype.getNegotiatedCipher = function() {
    return this._handle.getNegotiatedCipher();
};

QuicTLS.prototype.exportKeyingMaterial = function(labelBuffer, hashsize) {
    return this._handle.exportKeyingMaterial(labelBuffer, hashsize);
};

QuicTLS.prototype.exportEarlyKeyingMaterial = function(labelBuffer, hashsize) {
    return this._handle.exportEarlyKeyingMaterial(labelBuffer, hashsize);
};

QuicTLS.prototype.setSession = function(session) {
  if (typeof session === 'string')
    session = Buffer.from(session, 'latin1');
  this._handle.setSession(session);
};

QuicTLS.prototype.getSession = function() {
  if (this._handle) {
    return this._handle.getSession();
  }

  return null;
};

QuicTLS.prototype.isEarlyDataAllowed = function() {
  if (this._handle) {
    return this._handle.isEarlyDataAllowed();
  }

  return null;
};

QuicTLS.prototype.isSessionReused = function() {
  if (this._handle) {
    return this._handle.isSessionReused();
  }

  return null;
};

function onerror(e) {
    debug(e);
    this.owner.emit("error", e);
}

function onhandshakedone() {
    debug("hs done");
    this.owner.emit("handshakedone");
}

function onnewsession() {
    debug("on new session");
}

QuicTLS.prototype._init = function (isServer) {
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
    if (requestCert || rejectUnauthorized)
        ssl.setVerifyMode(requestCert, rejectUnauthorized);


    ssl.onerror = onerror;
    ssl.onhandshakedone = onhandshakedone;
    ssl.onnewsession = onnewsession;

    ssl.enableSessionCallbacks();
    if (isServer) {
        if (this.server) {
            if (this.server.listenerCount('OCSPRequest') > 0)
                ssl.enableCertCb();
        }
    } else {
        if (options.session)
            ssl.setSession(options.session);
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
        this._SNICallback = options.SNICallback;
        ssl.enableCertCb();
    }

    if (options.alpnProtocols) {
        // keep reference in secureContext not to be GC-ed
        var buff = convertProtocols(options.alpnProtocols);
        ssl._secureContext.alpnBuffer = buff;
        ssl.setALPNProtocols(ssl._secureContext.alpnBuffer);
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

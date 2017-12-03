'use strict';

require('internal/util').assertCrypto();

const assert = require('assert');
const crypto = require('crypto');
const util = require('util');
const { Buffer } = require('buffer');
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

    this.ssl = this._handle;

    //this.on('error', this._tlsError);

    this._init();

    this._qtlsWrapObject = this._callWrap(isServer);

    // Read on next tick so the caller has a chance to setup listeners
    process.nextTick(initRead, this, socket);
}


QuicTLS.prototype._callWrap = function (isServer) {
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

    if (isServer) {
        if (this.server) {
            if (this.server.listenerCount('resumeSession') > 0 ||
                this.server.listenerCount('newSession') > 0) {
                ssl.enableSessionCallbacks();
            }
            if (this.server.listenerCount('OCSPRequest') > 0)
                ssl.enableCertCb();
        }
    } else {
        if (options.session)
            ssl.setSession(options.session);
    }

    ssl.onerror = onerror;

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

    if (process.features.tls_alpn && options.ALPNProtocols) {
        // keep reference in secureContext not to be GC-ed
        ssl._secureContext.alpnBuffer = options.ALPNProtocols;
        ssl.setALPNProtocols(ssl._secureContext.alpnBuffer);
    }
};
function onerror(err) {
    debug("Error: " + msg);
}


exports.DEFAULT_CIPHERS = process.binding('constants').crypto.defaultCipherList;
exports.getCiphers = internalUtil.cachedResult(
    () => internalUtil.filterDuplicateStrings(binding.getSSLCiphers(), true)
);
exports.QuicTLS = QuicTLS;

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

'use strict';
const common = require('../common');
if (!common.hasCrypto)
  common.skip('missing crypto');

if (!common.hasIPv6)
  common.skip('no IPv6 support');

const assert = require('assert');
const https = require('https');
const dns = require('dns');
const fs = require('fs');

const opts = {
  key: fs.readFileSync(common.fixturesDir + '/keys/agent1-key.pem'),
  cert: fs.readFileSync(common.fixturesDir + '/keys/agent1-cert.pem'),
  ca: fs.readFileSync(common.fixturesDir + '/keys/ca1-cert.pem')
};

function runTest() {
  https.createServer(opts, common.mustCall(function(req, res) {
    this.close();
    res.end();
  })).listen(0, '::1', common.mustCall(function() {
    const options = {
      host: 'localhost',
      port: this.address().port,
      family: 6,
      rejectUnauthorized: false,
    };
    // Will fail with ECONNREFUSED if the address family is not honored.
    https.get(options, common.mustCall(function() {
      assert.strictEqual('::1', this.socket.remoteAddress);
      this.destroy();
    }));
  }));
}

dns.lookup('localhost', { family: 6, all: true }, (err, addresses) => {
  if (err) {
    if (err.code === 'ENOTFOUND')
      common.skip('localhost does not resolve to ::1');

    throw err;
  }

  if (addresses.some((val) => val.address === '::1'))
    runTest();
  else
    common.skip('localhost does not resolve to ::1');
});

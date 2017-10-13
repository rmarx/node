{
  'variables': {
    'openssl_defines_BSD-x86_64': [
      'DSO_DLFCN',
      'HAVE_DLFCN_H',
      'NDEBUG',
      'OPENSSL_THREADS',
      'OPENSSL_NO_DYNAMIC_ENGINE',
      'OPENSSL_PIC',
      'OPENSSL_IA32_SSE2',
      'OPENSSL_BN_ASM_MONT',
      'OPENSSL_BN_ASM_MONT5',
      'OPENSSL_BN_ASM_GF2m',
      'SHA1_ASM',
      'SHA256_ASM',
      'SHA512_ASM',
      'RC4_ASM',
      'MD5_ASM',
      'AES_ASM',
      'VPAES_ASM',
      'BSAES_ASM',
      'GHASH_ASM',
      'ECP_NISTZ256_ASM',
      'PADLOCK_ASM',
      'POLY1305_ASM',
    ],
    'openssl_cflags_BSD-x86_64': [
      '-DL_ENDIAN -Wall -O3 -pthread -D_THREAD_SAFE -D_REENTRANT',
    ],
    'openssl_ex_libs_BSD-x86_64': [
      '',
    ],
    'openssl_cli_srcs_BSD-x86_64': [
      'openssl/apps/app_rand.c',
      'openssl/apps/apps.c',
      'openssl/apps/asn1pars.c',
      'openssl/apps/ca.c',
      'openssl/apps/ciphers.c',
      'openssl/apps/cms.c',
      'openssl/apps/crl.c',
      'openssl/apps/crl2p7.c',
      'openssl/apps/dgst.c',
      'openssl/apps/dhparam.c',
      'openssl/apps/dsa.c',
      'openssl/apps/dsaparam.c',
      'openssl/apps/ec.c',
      'openssl/apps/ecparam.c',
      'openssl/apps/enc.c',
      'openssl/apps/engine.c',
      'openssl/apps/errstr.c',
      'openssl/apps/gendsa.c',
      'openssl/apps/genpkey.c',
      'openssl/apps/genrsa.c',
      'openssl/apps/nseq.c',
      'openssl/apps/ocsp.c',
      'openssl/apps/openssl.c',
      'openssl/apps/opt.c',
      'openssl/apps/passwd.c',
      'openssl/apps/pkcs12.c',
      'openssl/apps/pkcs7.c',
      'openssl/apps/pkcs8.c',
      'openssl/apps/pkey.c',
      'openssl/apps/pkeyparam.c',
      'openssl/apps/pkeyutl.c',
      'openssl/apps/prime.c',
      'openssl/apps/rand.c',
      'openssl/apps/rehash.c',
      'openssl/apps/req.c',
      'openssl/apps/rsa.c',
      'openssl/apps/rsautl.c',
      'openssl/apps/s_cb.c',
      'openssl/apps/s_client.c',
      'openssl/apps/s_server.c',
      'openssl/apps/s_socket.c',
      'openssl/apps/s_time.c',
      'openssl/apps/sess_id.c',
      'openssl/apps/smime.c',
      'openssl/apps/speed.c',
      'openssl/apps/spkac.c',
      'openssl/apps/srp.c',
      'openssl/apps/storeutl.c',
      'openssl/apps/ts.c',
      'openssl/apps/verify.c',
      'openssl/apps/version.c',
      'openssl/apps/x509.c',
    ],
  },
  'defines': ['<@(openssl_defines_BSD-x86_64)'],
  'cflags' : ['<@(openssl_cflags_BSD-x86_64)'],
  'libraries': ['<@(openssl_ex_libs_BSD-x86_64)'],
  'sources': ['<@(openssl_cli_srcs_BSD-x86_64)'],
}

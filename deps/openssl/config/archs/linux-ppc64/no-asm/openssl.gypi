{
  'variables': {
    'openssl_sources': [
      'openssl/ssl/bio_ssl.c',
      'openssl/ssl/d1_lib.c',
      'openssl/ssl/d1_msg.c',
      'openssl/ssl/d1_srtp.c',
      'openssl/ssl/methods.c',
      'openssl/ssl/packet.c',
      'openssl/ssl/pqueue.c',
      'openssl/ssl/record/dtls1_bitmap.c',
      'openssl/ssl/record/rec_layer_d1.c',
      'openssl/ssl/record/rec_layer_s3.c',
      'openssl/ssl/record/ssl3_buffer.c',
      'openssl/ssl/record/ssl3_record.c',
      'openssl/ssl/record/ssl3_record_tls13.c',
      'openssl/ssl/s3_cbc.c',
      'openssl/ssl/s3_enc.c',
      'openssl/ssl/s3_lib.c',
      'openssl/ssl/s3_msg.c',
      'openssl/ssl/ssl_asn1.c',
      'openssl/ssl/ssl_cert.c',
      'openssl/ssl/ssl_ciph.c',
      'openssl/ssl/ssl_conf.c',
      'openssl/ssl/ssl_err.c',
      'openssl/ssl/ssl_init.c',
      'openssl/ssl/ssl_lib.c',
      'openssl/ssl/ssl_mcnf.c',
      'openssl/ssl/ssl_rsa.c',
      'openssl/ssl/ssl_sess.c',
      'openssl/ssl/ssl_stat.c',
      'openssl/ssl/ssl_txt.c',
      'openssl/ssl/ssl_utst.c',
      'openssl/ssl/statem/extensions.c',
      'openssl/ssl/statem/extensions_clnt.c',
      'openssl/ssl/statem/extensions_cust.c',
      'openssl/ssl/statem/extensions_srvr.c',
      'openssl/ssl/statem/statem.c',
      'openssl/ssl/statem/statem_clnt.c',
      'openssl/ssl/statem/statem_dtls.c',
      'openssl/ssl/statem/statem_lib.c',
      'openssl/ssl/statem/statem_srvr.c',
      'openssl/ssl/t1_enc.c',
      'openssl/ssl/t1_lib.c',
      'openssl/ssl/t1_trce.c',
      'openssl/ssl/tls13_enc.c',
      'openssl/ssl/tls_srp.c',
      'openssl/crypto/aes/aes_cbc.c',
      'openssl/crypto/aes/aes_cfb.c',
      'openssl/crypto/aes/aes_core.c',
      'openssl/crypto/aes/aes_ecb.c',
      'openssl/crypto/aes/aes_ige.c',
      'openssl/crypto/aes/aes_misc.c',
      'openssl/crypto/aes/aes_ofb.c',
      'openssl/crypto/aes/aes_wrap.c',
      'openssl/crypto/asn1/a_bitstr.c',
      'openssl/crypto/asn1/a_d2i_fp.c',
      'openssl/crypto/asn1/a_digest.c',
      'openssl/crypto/asn1/a_dup.c',
      'openssl/crypto/asn1/a_gentm.c',
      'openssl/crypto/asn1/a_i2d_fp.c',
      'openssl/crypto/asn1/a_int.c',
      'openssl/crypto/asn1/a_mbstr.c',
      'openssl/crypto/asn1/a_object.c',
      'openssl/crypto/asn1/a_octet.c',
      'openssl/crypto/asn1/a_print.c',
      'openssl/crypto/asn1/a_sign.c',
      'openssl/crypto/asn1/a_strex.c',
      'openssl/crypto/asn1/a_strnid.c',
      'openssl/crypto/asn1/a_time.c',
      'openssl/crypto/asn1/a_type.c',
      'openssl/crypto/asn1/a_utctm.c',
      'openssl/crypto/asn1/a_utf8.c',
      'openssl/crypto/asn1/a_verify.c',
      'openssl/crypto/asn1/ameth_lib.c',
      'openssl/crypto/asn1/asn1_err.c',
      'openssl/crypto/asn1/asn1_gen.c',
      'openssl/crypto/asn1/asn1_item_list.c',
      'openssl/crypto/asn1/asn1_lib.c',
      'openssl/crypto/asn1/asn1_par.c',
      'openssl/crypto/asn1/asn_mime.c',
      'openssl/crypto/asn1/asn_moid.c',
      'openssl/crypto/asn1/asn_mstbl.c',
      'openssl/crypto/asn1/asn_pack.c',
      'openssl/crypto/asn1/bio_asn1.c',
      'openssl/crypto/asn1/bio_ndef.c',
      'openssl/crypto/asn1/d2i_pr.c',
      'openssl/crypto/asn1/d2i_pu.c',
      'openssl/crypto/asn1/evp_asn1.c',
      'openssl/crypto/asn1/f_int.c',
      'openssl/crypto/asn1/f_string.c',
      'openssl/crypto/asn1/i2d_pr.c',
      'openssl/crypto/asn1/i2d_pu.c',
      'openssl/crypto/asn1/n_pkey.c',
      'openssl/crypto/asn1/nsseq.c',
      'openssl/crypto/asn1/p5_pbe.c',
      'openssl/crypto/asn1/p5_pbev2.c',
      'openssl/crypto/asn1/p5_scrypt.c',
      'openssl/crypto/asn1/p8_pkey.c',
      'openssl/crypto/asn1/t_bitst.c',
      'openssl/crypto/asn1/t_pkey.c',
      'openssl/crypto/asn1/t_spki.c',
      'openssl/crypto/asn1/tasn_dec.c',
      'openssl/crypto/asn1/tasn_enc.c',
      'openssl/crypto/asn1/tasn_fre.c',
      'openssl/crypto/asn1/tasn_new.c',
      'openssl/crypto/asn1/tasn_prn.c',
      'openssl/crypto/asn1/tasn_scn.c',
      'openssl/crypto/asn1/tasn_typ.c',
      'openssl/crypto/asn1/tasn_utl.c',
      'openssl/crypto/asn1/x_algor.c',
      'openssl/crypto/asn1/x_bignum.c',
      'openssl/crypto/asn1/x_info.c',
      'openssl/crypto/asn1/x_int64.c',
      'openssl/crypto/asn1/x_long.c',
      'openssl/crypto/asn1/x_pkey.c',
      'openssl/crypto/asn1/x_sig.c',
      'openssl/crypto/asn1/x_spki.c',
      'openssl/crypto/asn1/x_val.c',
      'openssl/crypto/async/arch/async_null.c',
      'openssl/crypto/async/arch/async_posix.c',
      'openssl/crypto/async/arch/async_win.c',
      'openssl/crypto/async/async.c',
      'openssl/crypto/async/async_err.c',
      'openssl/crypto/async/async_wait.c',
      'openssl/crypto/bf/bf_cfb64.c',
      'openssl/crypto/bf/bf_ecb.c',
      'openssl/crypto/bf/bf_enc.c',
      'openssl/crypto/bf/bf_ofb64.c',
      'openssl/crypto/bf/bf_skey.c',
      'openssl/crypto/bio/b_addr.c',
      'openssl/crypto/bio/b_dump.c',
      'openssl/crypto/bio/b_print.c',
      'openssl/crypto/bio/b_sock.c',
      'openssl/crypto/bio/b_sock2.c',
      'openssl/crypto/bio/bf_buff.c',
      'openssl/crypto/bio/bf_lbuf.c',
      'openssl/crypto/bio/bf_nbio.c',
      'openssl/crypto/bio/bf_null.c',
      'openssl/crypto/bio/bio_cb.c',
      'openssl/crypto/bio/bio_err.c',
      'openssl/crypto/bio/bio_lib.c',
      'openssl/crypto/bio/bio_meth.c',
      'openssl/crypto/bio/bss_acpt.c',
      'openssl/crypto/bio/bss_bio.c',
      'openssl/crypto/bio/bss_conn.c',
      'openssl/crypto/bio/bss_dgram.c',
      'openssl/crypto/bio/bss_fd.c',
      'openssl/crypto/bio/bss_file.c',
      'openssl/crypto/bio/bss_log.c',
      'openssl/crypto/bio/bss_mem.c',
      'openssl/crypto/bio/bss_null.c',
      'openssl/crypto/bio/bss_sock.c',
      'openssl/crypto/blake2/blake2b.c',
      'openssl/crypto/blake2/blake2s.c',
      'openssl/crypto/blake2/m_blake2b.c',
      'openssl/crypto/blake2/m_blake2s.c',
      'openssl/crypto/bn/bn_add.c',
      'openssl/crypto/bn/bn_asm.c',
      'openssl/crypto/bn/bn_blind.c',
      'openssl/crypto/bn/bn_const.c',
      'openssl/crypto/bn/bn_ctx.c',
      'openssl/crypto/bn/bn_depr.c',
      'openssl/crypto/bn/bn_dh.c',
      'openssl/crypto/bn/bn_div.c',
      'openssl/crypto/bn/bn_err.c',
      'openssl/crypto/bn/bn_exp.c',
      'openssl/crypto/bn/bn_exp2.c',
      'openssl/crypto/bn/bn_gcd.c',
      'openssl/crypto/bn/bn_gf2m.c',
      'openssl/crypto/bn/bn_intern.c',
      'openssl/crypto/bn/bn_kron.c',
      'openssl/crypto/bn/bn_lib.c',
      'openssl/crypto/bn/bn_mod.c',
      'openssl/crypto/bn/bn_mont.c',
      'openssl/crypto/bn/bn_mpi.c',
      'openssl/crypto/bn/bn_mul.c',
      'openssl/crypto/bn/bn_nist.c',
      'openssl/crypto/bn/bn_prime.c',
      'openssl/crypto/bn/bn_print.c',
      'openssl/crypto/bn/bn_rand.c',
      'openssl/crypto/bn/bn_recp.c',
      'openssl/crypto/bn/bn_shift.c',
      'openssl/crypto/bn/bn_sqr.c',
      'openssl/crypto/bn/bn_sqrt.c',
      'openssl/crypto/bn/bn_srp.c',
      'openssl/crypto/bn/bn_word.c',
      'openssl/crypto/bn/bn_x931p.c',
      'openssl/crypto/buffer/buf_err.c',
      'openssl/crypto/buffer/buffer.c',
      'openssl/crypto/camellia/camellia.c',
      'openssl/crypto/camellia/cmll_cbc.c',
      'openssl/crypto/camellia/cmll_cfb.c',
      'openssl/crypto/camellia/cmll_ctr.c',
      'openssl/crypto/camellia/cmll_ecb.c',
      'openssl/crypto/camellia/cmll_misc.c',
      'openssl/crypto/camellia/cmll_ofb.c',
      'openssl/crypto/cast/c_cfb64.c',
      'openssl/crypto/cast/c_ecb.c',
      'openssl/crypto/cast/c_enc.c',
      'openssl/crypto/cast/c_ofb64.c',
      'openssl/crypto/cast/c_skey.c',
      'openssl/crypto/chacha/chacha_enc.c',
      'openssl/crypto/cmac/cm_ameth.c',
      'openssl/crypto/cmac/cm_pmeth.c',
      'openssl/crypto/cmac/cmac.c',
      'openssl/crypto/cms/cms_asn1.c',
      'openssl/crypto/cms/cms_att.c',
      'openssl/crypto/cms/cms_cd.c',
      'openssl/crypto/cms/cms_dd.c',
      'openssl/crypto/cms/cms_enc.c',
      'openssl/crypto/cms/cms_env.c',
      'openssl/crypto/cms/cms_err.c',
      'openssl/crypto/cms/cms_ess.c',
      'openssl/crypto/cms/cms_io.c',
      'openssl/crypto/cms/cms_kari.c',
      'openssl/crypto/cms/cms_lib.c',
      'openssl/crypto/cms/cms_pwri.c',
      'openssl/crypto/cms/cms_sd.c',
      'openssl/crypto/cms/cms_smime.c',
      'openssl/crypto/conf/conf_api.c',
      'openssl/crypto/conf/conf_def.c',
      'openssl/crypto/conf/conf_err.c',
      'openssl/crypto/conf/conf_lib.c',
      'openssl/crypto/conf/conf_mall.c',
      'openssl/crypto/conf/conf_mod.c',
      'openssl/crypto/conf/conf_sap.c',
      'openssl/crypto/cpt_err.c',
      'openssl/crypto/cryptlib.c',
      'openssl/crypto/ct/ct_b64.c',
      'openssl/crypto/ct/ct_err.c',
      'openssl/crypto/ct/ct_log.c',
      'openssl/crypto/ct/ct_oct.c',
      'openssl/crypto/ct/ct_policy.c',
      'openssl/crypto/ct/ct_prn.c',
      'openssl/crypto/ct/ct_sct.c',
      'openssl/crypto/ct/ct_sct_ctx.c',
      'openssl/crypto/ct/ct_vfy.c',
      'openssl/crypto/ct/ct_x509v3.c',
      'openssl/crypto/ctype.c',
      'openssl/crypto/cversion.c',
      'openssl/crypto/des/cbc_cksm.c',
      'openssl/crypto/des/cbc_enc.c',
      'openssl/crypto/des/cfb64ede.c',
      'openssl/crypto/des/cfb64enc.c',
      'openssl/crypto/des/cfb_enc.c',
      'openssl/crypto/des/des_enc.c',
      'openssl/crypto/des/ecb3_enc.c',
      'openssl/crypto/des/ecb_enc.c',
      'openssl/crypto/des/fcrypt.c',
      'openssl/crypto/des/fcrypt_b.c',
      'openssl/crypto/des/ofb64ede.c',
      'openssl/crypto/des/ofb64enc.c',
      'openssl/crypto/des/ofb_enc.c',
      'openssl/crypto/des/pcbc_enc.c',
      'openssl/crypto/des/qud_cksm.c',
      'openssl/crypto/des/rand_key.c',
      'openssl/crypto/des/set_key.c',
      'openssl/crypto/des/str2key.c',
      'openssl/crypto/des/xcbc_enc.c',
      'openssl/crypto/dh/dh_ameth.c',
      'openssl/crypto/dh/dh_asn1.c',
      'openssl/crypto/dh/dh_check.c',
      'openssl/crypto/dh/dh_depr.c',
      'openssl/crypto/dh/dh_err.c',
      'openssl/crypto/dh/dh_gen.c',
      'openssl/crypto/dh/dh_kdf.c',
      'openssl/crypto/dh/dh_key.c',
      'openssl/crypto/dh/dh_lib.c',
      'openssl/crypto/dh/dh_meth.c',
      'openssl/crypto/dh/dh_pmeth.c',
      'openssl/crypto/dh/dh_prn.c',
      'openssl/crypto/dh/dh_rfc5114.c',
      'openssl/crypto/dh/dh_rfc7919.c',
      'openssl/crypto/dsa/dsa_ameth.c',
      'openssl/crypto/dsa/dsa_asn1.c',
      'openssl/crypto/dsa/dsa_depr.c',
      'openssl/crypto/dsa/dsa_err.c',
      'openssl/crypto/dsa/dsa_gen.c',
      'openssl/crypto/dsa/dsa_key.c',
      'openssl/crypto/dsa/dsa_lib.c',
      'openssl/crypto/dsa/dsa_meth.c',
      'openssl/crypto/dsa/dsa_ossl.c',
      'openssl/crypto/dsa/dsa_pmeth.c',
      'openssl/crypto/dsa/dsa_prn.c',
      'openssl/crypto/dsa/dsa_sign.c',
      'openssl/crypto/dsa/dsa_vrf.c',
      'openssl/crypto/dso/dso_dl.c',
      'openssl/crypto/dso/dso_dlfcn.c',
      'openssl/crypto/dso/dso_err.c',
      'openssl/crypto/dso/dso_lib.c',
      'openssl/crypto/dso/dso_openssl.c',
      'openssl/crypto/dso/dso_vms.c',
      'openssl/crypto/dso/dso_win32.c',
      'openssl/crypto/ebcdic.c',
      'openssl/crypto/ec/curve25519.c',
      'openssl/crypto/ec/ec2_mult.c',
      'openssl/crypto/ec/ec2_oct.c',
      'openssl/crypto/ec/ec2_smpl.c',
      'openssl/crypto/ec/ec_ameth.c',
      'openssl/crypto/ec/ec_asn1.c',
      'openssl/crypto/ec/ec_check.c',
      'openssl/crypto/ec/ec_curve.c',
      'openssl/crypto/ec/ec_cvt.c',
      'openssl/crypto/ec/ec_err.c',
      'openssl/crypto/ec/ec_key.c',
      'openssl/crypto/ec/ec_kmeth.c',
      'openssl/crypto/ec/ec_lib.c',
      'openssl/crypto/ec/ec_mult.c',
      'openssl/crypto/ec/ec_oct.c',
      'openssl/crypto/ec/ec_pmeth.c',
      'openssl/crypto/ec/ec_print.c',
      'openssl/crypto/ec/ecdh_kdf.c',
      'openssl/crypto/ec/ecdh_ossl.c',
      'openssl/crypto/ec/ecdsa_ossl.c',
      'openssl/crypto/ec/ecdsa_sign.c',
      'openssl/crypto/ec/ecdsa_vrf.c',
      'openssl/crypto/ec/eck_prn.c',
      'openssl/crypto/ec/ecp_mont.c',
      'openssl/crypto/ec/ecp_nist.c',
      'openssl/crypto/ec/ecp_nistp224.c',
      'openssl/crypto/ec/ecp_nistp256.c',
      'openssl/crypto/ec/ecp_nistp521.c',
      'openssl/crypto/ec/ecp_nistputil.c',
      'openssl/crypto/ec/ecp_oct.c',
      'openssl/crypto/ec/ecp_smpl.c',
      'openssl/crypto/ec/ecx_meth.c',
      'openssl/crypto/engine/eng_all.c',
      'openssl/crypto/engine/eng_cnf.c',
      'openssl/crypto/engine/eng_ctrl.c',
      'openssl/crypto/engine/eng_dyn.c',
      'openssl/crypto/engine/eng_err.c',
      'openssl/crypto/engine/eng_fat.c',
      'openssl/crypto/engine/eng_init.c',
      'openssl/crypto/engine/eng_lib.c',
      'openssl/crypto/engine/eng_list.c',
      'openssl/crypto/engine/eng_openssl.c',
      'openssl/crypto/engine/eng_pkey.c',
      'openssl/crypto/engine/eng_rdrand.c',
      'openssl/crypto/engine/eng_table.c',
      'openssl/crypto/engine/tb_asnmth.c',
      'openssl/crypto/engine/tb_cipher.c',
      'openssl/crypto/engine/tb_dh.c',
      'openssl/crypto/engine/tb_digest.c',
      'openssl/crypto/engine/tb_dsa.c',
      'openssl/crypto/engine/tb_eckey.c',
      'openssl/crypto/engine/tb_pkmeth.c',
      'openssl/crypto/engine/tb_rand.c',
      'openssl/crypto/engine/tb_rsa.c',
      'openssl/crypto/err/err.c',
      'openssl/crypto/err/err_all.c',
      'openssl/crypto/err/err_prn.c',
      'openssl/crypto/evp/bio_b64.c',
      'openssl/crypto/evp/bio_enc.c',
      'openssl/crypto/evp/bio_md.c',
      'openssl/crypto/evp/bio_ok.c',
      'openssl/crypto/evp/c_allc.c',
      'openssl/crypto/evp/c_alld.c',
      'openssl/crypto/evp/cmeth_lib.c',
      'openssl/crypto/evp/digest.c',
      'openssl/crypto/evp/e_aes.c',
      'openssl/crypto/evp/e_aes_cbc_hmac_sha1.c',
      'openssl/crypto/evp/e_aes_cbc_hmac_sha256.c',
      'openssl/crypto/evp/e_aria.c',
      'openssl/crypto/evp/e_bf.c',
      'openssl/crypto/evp/e_camellia.c',
      'openssl/crypto/evp/e_cast.c',
      'openssl/crypto/evp/e_chacha20_poly1305.c',
      'openssl/crypto/evp/e_des.c',
      'openssl/crypto/evp/e_des3.c',
      'openssl/crypto/evp/e_idea.c',
      'openssl/crypto/evp/e_null.c',
      'openssl/crypto/evp/e_old.c',
      'openssl/crypto/evp/e_rc2.c',
      'openssl/crypto/evp/e_rc4.c',
      'openssl/crypto/evp/e_rc4_hmac_md5.c',
      'openssl/crypto/evp/e_rc5.c',
      'openssl/crypto/evp/e_seed.c',
      'openssl/crypto/evp/e_xcbc_d.c',
      'openssl/crypto/evp/encode.c',
      'openssl/crypto/evp/evp_cnf.c',
      'openssl/crypto/evp/evp_enc.c',
      'openssl/crypto/evp/evp_err.c',
      'openssl/crypto/evp/evp_key.c',
      'openssl/crypto/evp/evp_lib.c',
      'openssl/crypto/evp/evp_pbe.c',
      'openssl/crypto/evp/evp_pkey.c',
      'openssl/crypto/evp/m_md2.c',
      'openssl/crypto/evp/m_md4.c',
      'openssl/crypto/evp/m_md5.c',
      'openssl/crypto/evp/m_md5_sha1.c',
      'openssl/crypto/evp/m_mdc2.c',
      'openssl/crypto/evp/m_null.c',
      'openssl/crypto/evp/m_ripemd.c',
      'openssl/crypto/evp/m_sha1.c',
      'openssl/crypto/evp/m_sha3.c',
      'openssl/crypto/evp/m_sigver.c',
      'openssl/crypto/evp/m_wp.c',
      'openssl/crypto/evp/names.c',
      'openssl/crypto/evp/p5_crpt.c',
      'openssl/crypto/evp/p5_crpt2.c',
      'openssl/crypto/evp/p_dec.c',
      'openssl/crypto/evp/p_enc.c',
      'openssl/crypto/evp/p_lib.c',
      'openssl/crypto/evp/p_open.c',
      'openssl/crypto/evp/p_seal.c',
      'openssl/crypto/evp/p_sign.c',
      'openssl/crypto/evp/p_verify.c',
      'openssl/crypto/evp/pbe_scrypt.c',
      'openssl/crypto/evp/pmeth_fn.c',
      'openssl/crypto/evp/pmeth_gn.c',
      'openssl/crypto/evp/pmeth_lib.c',
      'openssl/crypto/ex_data.c',
      'openssl/crypto/hmac/hm_ameth.c',
      'openssl/crypto/hmac/hm_pmeth.c',
      'openssl/crypto/hmac/hmac.c',
      'openssl/crypto/idea/i_cbc.c',
      'openssl/crypto/idea/i_cfb64.c',
      'openssl/crypto/idea/i_ecb.c',
      'openssl/crypto/idea/i_ofb64.c',
      'openssl/crypto/idea/i_skey.c',
      'openssl/crypto/init.c',
      'openssl/crypto/kdf/hkdf.c',
      'openssl/crypto/kdf/kdf_err.c',
      'openssl/crypto/kdf/scrypt.c',
      'openssl/crypto/kdf/tls1_prf.c',
      'openssl/crypto/lhash/lh_stats.c',
      'openssl/crypto/lhash/lhash.c',
      'openssl/crypto/md4/md4_dgst.c',
      'openssl/crypto/md4/md4_one.c',
      'openssl/crypto/md5/md5_dgst.c',
      'openssl/crypto/md5/md5_one.c',
      'openssl/crypto/mdc2/mdc2_one.c',
      'openssl/crypto/mdc2/mdc2dgst.c',
      'openssl/crypto/mem.c',
      'openssl/crypto/mem_clr.c',
      'openssl/crypto/mem_dbg.c',
      'openssl/crypto/mem_sec.c',
      'openssl/crypto/modes/cbc128.c',
      'openssl/crypto/modes/ccm128.c',
      'openssl/crypto/modes/cfb128.c',
      'openssl/crypto/modes/ctr128.c',
      'openssl/crypto/modes/cts128.c',
      'openssl/crypto/modes/gcm128.c',
      'openssl/crypto/modes/ocb128.c',
      'openssl/crypto/modes/ofb128.c',
      'openssl/crypto/modes/wrap128.c',
      'openssl/crypto/modes/xts128.c',
      'openssl/crypto/o_dir.c',
      'openssl/crypto/o_fips.c',
      'openssl/crypto/o_fopen.c',
      'openssl/crypto/o_init.c',
      'openssl/crypto/o_str.c',
      'openssl/crypto/o_time.c',
      'openssl/crypto/objects/o_names.c',
      'openssl/crypto/objects/obj_dat.c',
      'openssl/crypto/objects/obj_err.c',
      'openssl/crypto/objects/obj_lib.c',
      'openssl/crypto/objects/obj_xref.c',
      'openssl/crypto/ocsp/ocsp_asn.c',
      'openssl/crypto/ocsp/ocsp_cl.c',
      'openssl/crypto/ocsp/ocsp_err.c',
      'openssl/crypto/ocsp/ocsp_ext.c',
      'openssl/crypto/ocsp/ocsp_ht.c',
      'openssl/crypto/ocsp/ocsp_lib.c',
      'openssl/crypto/ocsp/ocsp_prn.c',
      'openssl/crypto/ocsp/ocsp_srv.c',
      'openssl/crypto/ocsp/ocsp_vfy.c',
      'openssl/crypto/ocsp/v3_ocsp.c',
      'openssl/crypto/pem/pem_all.c',
      'openssl/crypto/pem/pem_err.c',
      'openssl/crypto/pem/pem_info.c',
      'openssl/crypto/pem/pem_lib.c',
      'openssl/crypto/pem/pem_oth.c',
      'openssl/crypto/pem/pem_pk8.c',
      'openssl/crypto/pem/pem_pkey.c',
      'openssl/crypto/pem/pem_sign.c',
      'openssl/crypto/pem/pem_x509.c',
      'openssl/crypto/pem/pem_xaux.c',
      'openssl/crypto/pem/pvkfmt.c',
      'openssl/crypto/pkcs12/p12_add.c',
      'openssl/crypto/pkcs12/p12_asn.c',
      'openssl/crypto/pkcs12/p12_attr.c',
      'openssl/crypto/pkcs12/p12_crpt.c',
      'openssl/crypto/pkcs12/p12_crt.c',
      'openssl/crypto/pkcs12/p12_decr.c',
      'openssl/crypto/pkcs12/p12_init.c',
      'openssl/crypto/pkcs12/p12_key.c',
      'openssl/crypto/pkcs12/p12_kiss.c',
      'openssl/crypto/pkcs12/p12_mutl.c',
      'openssl/crypto/pkcs12/p12_npas.c',
      'openssl/crypto/pkcs12/p12_p8d.c',
      'openssl/crypto/pkcs12/p12_p8e.c',
      'openssl/crypto/pkcs12/p12_sbag.c',
      'openssl/crypto/pkcs12/p12_utl.c',
      'openssl/crypto/pkcs12/pk12err.c',
      'openssl/crypto/pkcs7/bio_pk7.c',
      'openssl/crypto/pkcs7/pk7_asn1.c',
      'openssl/crypto/pkcs7/pk7_attr.c',
      'openssl/crypto/pkcs7/pk7_doit.c',
      'openssl/crypto/pkcs7/pk7_lib.c',
      'openssl/crypto/pkcs7/pk7_mime.c',
      'openssl/crypto/pkcs7/pk7_smime.c',
      'openssl/crypto/pkcs7/pkcs7err.c',
      'openssl/crypto/poly1305/poly1305.c',
      'openssl/crypto/poly1305/poly1305_ameth.c',
      'openssl/crypto/poly1305/poly1305_pmeth.c',
      'openssl/crypto/rand/drbg_lib.c',
      'openssl/crypto/rand/drbg_rand.c',
      'openssl/crypto/rand/rand_egd.c',
      'openssl/crypto/rand/rand_err.c',
      'openssl/crypto/rand/rand_lib.c',
      'openssl/crypto/rand/rand_unix.c',
      'openssl/crypto/rand/rand_vms.c',
      'openssl/crypto/rand/rand_win.c',
      'openssl/crypto/rand/randfile.c',
      'openssl/crypto/rc2/rc2_cbc.c',
      'openssl/crypto/rc2/rc2_ecb.c',
      'openssl/crypto/rc2/rc2_skey.c',
      'openssl/crypto/rc2/rc2cfb64.c',
      'openssl/crypto/rc2/rc2ofb64.c',
      'openssl/crypto/rc4/rc4_enc.c',
      'openssl/crypto/rc4/rc4_skey.c',
      'openssl/crypto/ripemd/rmd_dgst.c',
      'openssl/crypto/ripemd/rmd_one.c',
      'openssl/crypto/rsa/rsa_ameth.c',
      'openssl/crypto/rsa/rsa_asn1.c',
      'openssl/crypto/rsa/rsa_chk.c',
      'openssl/crypto/rsa/rsa_crpt.c',
      'openssl/crypto/rsa/rsa_depr.c',
      'openssl/crypto/rsa/rsa_err.c',
      'openssl/crypto/rsa/rsa_gen.c',
      'openssl/crypto/rsa/rsa_lib.c',
      'openssl/crypto/rsa/rsa_meth.c',
      'openssl/crypto/rsa/rsa_none.c',
      'openssl/crypto/rsa/rsa_oaep.c',
      'openssl/crypto/rsa/rsa_ossl.c',
      'openssl/crypto/rsa/rsa_pk1.c',
      'openssl/crypto/rsa/rsa_pmeth.c',
      'openssl/crypto/rsa/rsa_prn.c',
      'openssl/crypto/rsa/rsa_pss.c',
      'openssl/crypto/rsa/rsa_saos.c',
      'openssl/crypto/rsa/rsa_sign.c',
      'openssl/crypto/rsa/rsa_ssl.c',
      'openssl/crypto/rsa/rsa_x931.c',
      'openssl/crypto/rsa/rsa_x931g.c',
      'openssl/crypto/seed/seed.c',
      'openssl/crypto/seed/seed_cbc.c',
      'openssl/crypto/seed/seed_cfb.c',
      'openssl/crypto/seed/seed_ecb.c',
      'openssl/crypto/seed/seed_ofb.c',
      'openssl/crypto/sha/keccak1600.c',
      'openssl/crypto/sha/sha1_one.c',
      'openssl/crypto/sha/sha1dgst.c',
      'openssl/crypto/sha/sha256.c',
      'openssl/crypto/sha/sha512.c',
      'openssl/crypto/siphash/siphash.c',
      'openssl/crypto/siphash/siphash_ameth.c',
      'openssl/crypto/siphash/siphash_pmeth.c',
      'openssl/crypto/srp/srp_lib.c',
      'openssl/crypto/srp/srp_vfy.c',
      'openssl/crypto/stack/stack.c',
      'openssl/crypto/store/loader_file.c',
      'openssl/crypto/store/store_err.c',
      'openssl/crypto/store/store_init.c',
      'openssl/crypto/store/store_lib.c',
      'openssl/crypto/store/store_register.c',
      'openssl/crypto/store/store_strings.c',
      'openssl/crypto/threads_none.c',
      'openssl/crypto/threads_pthread.c',
      'openssl/crypto/threads_win.c',
      'openssl/crypto/ts/ts_asn1.c',
      'openssl/crypto/ts/ts_conf.c',
      'openssl/crypto/ts/ts_err.c',
      'openssl/crypto/ts/ts_lib.c',
      'openssl/crypto/ts/ts_req_print.c',
      'openssl/crypto/ts/ts_req_utils.c',
      'openssl/crypto/ts/ts_rsp_print.c',
      'openssl/crypto/ts/ts_rsp_sign.c',
      'openssl/crypto/ts/ts_rsp_utils.c',
      'openssl/crypto/ts/ts_rsp_verify.c',
      'openssl/crypto/ts/ts_verify_ctx.c',
      'openssl/crypto/txt_db/txt_db.c',
      'openssl/crypto/ui/ui_err.c',
      'openssl/crypto/ui/ui_lib.c',
      'openssl/crypto/ui/ui_null.c',
      'openssl/crypto/ui/ui_openssl.c',
      'openssl/crypto/ui/ui_util.c',
      'openssl/crypto/uid.c',
      'openssl/crypto/whrlpool/wp_block.c',
      'openssl/crypto/whrlpool/wp_dgst.c',
      'openssl/crypto/x509/by_dir.c',
      'openssl/crypto/x509/by_file.c',
      'openssl/crypto/x509/t_crl.c',
      'openssl/crypto/x509/t_req.c',
      'openssl/crypto/x509/t_x509.c',
      'openssl/crypto/x509/x509_att.c',
      'openssl/crypto/x509/x509_cmp.c',
      'openssl/crypto/x509/x509_d2.c',
      'openssl/crypto/x509/x509_def.c',
      'openssl/crypto/x509/x509_err.c',
      'openssl/crypto/x509/x509_ext.c',
      'openssl/crypto/x509/x509_lu.c',
      'openssl/crypto/x509/x509_obj.c',
      'openssl/crypto/x509/x509_r2x.c',
      'openssl/crypto/x509/x509_req.c',
      'openssl/crypto/x509/x509_set.c',
      'openssl/crypto/x509/x509_trs.c',
      'openssl/crypto/x509/x509_txt.c',
      'openssl/crypto/x509/x509_v3.c',
      'openssl/crypto/x509/x509_vfy.c',
      'openssl/crypto/x509/x509_vpm.c',
      'openssl/crypto/x509/x509cset.c',
      'openssl/crypto/x509/x509name.c',
      'openssl/crypto/x509/x509rset.c',
      'openssl/crypto/x509/x509spki.c',
      'openssl/crypto/x509/x509type.c',
      'openssl/crypto/x509/x_all.c',
      'openssl/crypto/x509/x_attrib.c',
      'openssl/crypto/x509/x_crl.c',
      'openssl/crypto/x509/x_exten.c',
      'openssl/crypto/x509/x_name.c',
      'openssl/crypto/x509/x_pubkey.c',
      'openssl/crypto/x509/x_req.c',
      'openssl/crypto/x509/x_x509.c',
      'openssl/crypto/x509/x_x509a.c',
      'openssl/crypto/x509v3/pcy_cache.c',
      'openssl/crypto/x509v3/pcy_data.c',
      'openssl/crypto/x509v3/pcy_lib.c',
      'openssl/crypto/x509v3/pcy_map.c',
      'openssl/crypto/x509v3/pcy_node.c',
      'openssl/crypto/x509v3/pcy_tree.c',
      'openssl/crypto/x509v3/v3_addr.c',
      'openssl/crypto/x509v3/v3_admis.c',
      'openssl/crypto/x509v3/v3_akey.c',
      'openssl/crypto/x509v3/v3_akeya.c',
      'openssl/crypto/x509v3/v3_alt.c',
      'openssl/crypto/x509v3/v3_asid.c',
      'openssl/crypto/x509v3/v3_bcons.c',
      'openssl/crypto/x509v3/v3_bitst.c',
      'openssl/crypto/x509v3/v3_conf.c',
      'openssl/crypto/x509v3/v3_cpols.c',
      'openssl/crypto/x509v3/v3_crld.c',
      'openssl/crypto/x509v3/v3_enum.c',
      'openssl/crypto/x509v3/v3_extku.c',
      'openssl/crypto/x509v3/v3_genn.c',
      'openssl/crypto/x509v3/v3_ia5.c',
      'openssl/crypto/x509v3/v3_info.c',
      'openssl/crypto/x509v3/v3_int.c',
      'openssl/crypto/x509v3/v3_lib.c',
      'openssl/crypto/x509v3/v3_ncons.c',
      'openssl/crypto/x509v3/v3_pci.c',
      'openssl/crypto/x509v3/v3_pcia.c',
      'openssl/crypto/x509v3/v3_pcons.c',
      'openssl/crypto/x509v3/v3_pku.c',
      'openssl/crypto/x509v3/v3_pmaps.c',
      'openssl/crypto/x509v3/v3_prn.c',
      'openssl/crypto/x509v3/v3_purp.c',
      'openssl/crypto/x509v3/v3_skey.c',
      'openssl/crypto/x509v3/v3_sxnet.c',
      'openssl/crypto/x509v3/v3_tlsf.c',
      'openssl/crypto/x509v3/v3_utl.c',
      'openssl/crypto/x509v3/v3err.c',
      'openssl/engines/e_capi.c',
      'openssl/engines/e_padlock.c',
    ],
    'openssl_sources_linux-ppc64': [
    ],
    'openssl_defines_linux-ppc64': [
      'DSO_DLFCN',
      'HAVE_DLFCN_H',
      'NDEBUG',
      'OPENSSL_THREADS',
      'OPENSSL_NO_DYNAMIC_ENGINE',
      'OPENSSL_PIC',
    ],
    'openssl_cflags_linux-ppc64': [
      '-Wall -O3 -pthread -m64 -DB_ENDIAN',
    ],
    'openssl_ex_libs_linux-ppc64': [
      '-ldl',
    ],
  },
  'include_dirs': [
    '.',
    './include',
    './crypto',
    './crypto/include/internal',
  ],
  'defines': ['<@(openssl_defines_linux-ppc64)'],
  'cflags' : ['<@(openssl_cflags_linux-ppc64)'],
  'libraries': ['<@(openssl_ex_libs_linux-ppc64)'],
  'sources': ['<@(openssl_sources)', '<@(openssl_sources_linux-ppc64)'],
}

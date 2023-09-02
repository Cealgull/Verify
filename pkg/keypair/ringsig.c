#include "ringsig.h"

#include "base64.h"

#define BN_SIZE 32
#define POINT_SIZE 65
#define MAX_BNBUF 128
#define MAX_POINTSBUF 4160

static ringsig_keyset_spec_t keyset_spec;
static ringsig_keyset_extern_t keyset_extern;

static void ringsig_keyset_spec_init(ringsig_keyset_spec_t *spec, int nr_mem);
static void ringsig_keyset_extern_init(const ringsig_keyset_spec_t *spec,
                                       ringsig_keyset_extern_t *ext);

static int ringsig_prehash(EVP_MD_CTX *mctx, const char *msg, int msg_len);
static int ringsig_hash2BN(const EVP_MD_CTX *mctx, const char *msg, int msg_len,
                           BIGNUM *bn);
static int ringsig_hashPOINT2BN(const EVP_MD_CTX *mctx, const EC_GROUP *g,
                                const EC_POINT *point, BIGNUM *bn);
static int ringsig_keypair_extern2spec(const ringsig_keypair_extern_t *ext,
                                       ringsig_keypair_spec_t *spec);
static int ringsig_b642BN(const char *b64, BIGNUM *bn);
static int ringsig_b642POINTS(const char *b64, int nr_mem, const EC_GROUP *g,
                              EC_POINT **pubs);
static int ringsig_BN2b64(const BIGNUM *bn, char *b64);
static int ringsig_POINTS2b64(const EC_GROUP *g, const EC_POINT **ps,
                              int nr_mem, char *b64);
static void ringsig_keypair_spec_free(ringsig_keypair_spec_t *spec);

static int ringsig_prehash(EVP_MD_CTX *mctx, const char *msg, int msg_len) {
  EVP_DigestInit(mctx, EVP_sm3());
  EVP_DigestUpdate(mctx, msg, msg_len);
  return 1;
}

static int ringsig_hash2BN(const EVP_MD_CTX *mctx, const char *msg, int msg_len,
                           BIGNUM *bn) {
  char buf[BN_SIZE] = {0};

  EVP_MD_CTX *mctx_bn = EVP_MD_CTX_new();
  EVP_MD_CTX_copy(mctx_bn, mctx);
  EVP_DigestUpdate(mctx_bn, msg, msg_len);

  uint32_t sz = BN_SIZE;
  EVP_DigestFinal(mctx_bn, (uint8_t *)buf, &sz);
  EVP_MD_CTX_free(mctx_bn);
  BN_bin2bn((const unsigned char *)buf, BN_SIZE, bn);

  return 1;
}

static int ringsig_hashPOINT2BN(const EVP_MD_CTX *mctx, const EC_GROUP *g,
                                const EC_POINT *point, BIGNUM *bn) {
  char buf[MAX_BNBUF] = {0};
  uint32_t sz = POINT_SIZE;
  EC_POINT_point2oct(g, point, POINT_CONVERSION_UNCOMPRESSED, (uint8_t *)buf,
                     sz, NULL);
  ringsig_hash2BN(mctx, buf, sz, bn);
  return 1;
}

int ringsig_sign_len(int nr_mem) {
  return nr_mem * (BN_SIZE + POINT_SIZE) + BN_SIZE;
}

int ringsig_signb64_len(int nr_mem) {
  return Base64encode_len(ringsig_sign_len(nr_mem));
}

static int ringsig_b642BN(const char *b64, BIGNUM *bn) {
  char buf[MAX_BNBUF] = {0};
  Base64decode(buf, b64);
  BN_bin2bn((const unsigned char *)buf, BN_SIZE, bn);
  return 1;
}

static int ringsig_b642POINTS(const char *b64, int nr_mem, const EC_GROUP *g,
                              EC_POINT **pubs) {
  char *buf = (char *)calloc(sizeof(char), nr_mem * POINT_SIZE);
  int sz = POINT_SIZE;
  Base64decode(buf, b64);
  for (int i = 0; i < nr_mem; i++) {
    pubs[i] = EC_POINT_new(g);
    EC_POINT_oct2point(g, pubs[i], (const uint8_t *)buf + i * sz, sz, NULL);
  }
  free(buf);
  return 1;
}

static int ringsig_BN2b64(const BIGNUM *bn, char *b64) {
  char buf[MAX_BNBUF] = {0};
  BN_bn2bin(bn, (unsigned char *)buf);
  Base64encode(b64, buf, BN_SIZE);
  return 1;
}

static int ringsig_POINTS2b64(const EC_GROUP *g, const EC_POINT **ps,
                              int nr_mem, char *b64) {
  char *buf = (char *)calloc(sizeof(char), nr_mem * POINT_SIZE);
  int sz = POINT_SIZE;
  for (int i = 0; i < nr_mem; i++) {
    uint8_t *p = (uint8_t *)buf + i * sz;
    EC_POINT_point2oct(g, ps[i], POINT_CONVERSION_UNCOMPRESSED, p, sz, NULL);
  }
  Base64encode(b64, buf, nr_mem * sz);
  free(buf);
  return 1;
}

static int ringsig_keypair_extern2spec(const ringsig_keypair_extern_t *ext,
                                       ringsig_keypair_spec_t *spec) {
  spec->nr_mem = ext->nr_mem;
  spec->mine = ext->mine;
  spec->priv = BN_new();
  spec->pubs = (EC_POINT **)calloc(sizeof(EC_POINT *), ext->nr_mem);
  spec->g = EC_GROUP_new_by_curve_name(NID_sm2);

  ringsig_b642BN(ext->priv, spec->priv);
  ringsig_b642POINTS(ext->pubs, ext->nr_mem, spec->g, spec->pubs);
  return 1;
}

static void ringsig_keypair_spec_free(ringsig_keypair_spec_t *spec) {
  BN_free(spec->priv);
  for (int i = 0; i < spec->nr_mem; i++) EC_POINT_free(spec->pubs[i]);
  EC_GROUP_free(spec->g);
}

static BIGNUM *ringsig_BN_rand() {
  BIGNUM *bn = BN_new();
  BN_rand(bn, BN_SIZE * 8, BN_RAND_TOP_TWO, BN_RAND_BOTTOM_ANY);
  return bn;
}

int ringsig_sign(const ringsig_keypair_extern_t *ext, const char *msg,
                 int msg_len, char *sig) {
  int n = ext->nr_mem;
  int pi = ext->mine;
  ringsig_keypair_spec_t spec;
  ringsig_keypair_extern2spec(ext, &spec);

  BIGNUM *k = ringsig_BN_rand();
  BIGNUM *order = BN_new();
  BIGNUM **r = (BIGNUM **)calloc(sizeof(BIGNUM *), ext->nr_mem);
  BIGNUM **c = (BIGNUM **)calloc(sizeof(BIGNUM *), ext->nr_mem);
  BN_CTX *bctx = BN_CTX_new();
  EC_POINT *p = EC_POINT_new(spec.g);
  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  int ret = 0;

  ringsig_prehash(mctx, msg, msg_len);

  c[(pi + 1) % n] = BN_new();

  EC_GROUP_get_order(spec.g, order, NULL);
  EC_POINT_mul(spec.g, p, k, NULL, NULL, NULL);
  ringsig_hashPOINT2BN(mctx, spec.g, p, c[(pi + 1) % n]);

  for (int i = (pi + 1) % n; i != pi; i = (i + 1) % n) {
    r[i] = ringsig_BN_rand();
    c[(i + 1) % n] = BN_new();
    EC_POINT_mul(spec.g, p, r[i], spec.pubs[i], c[i], NULL);
    ringsig_hashPOINT2BN(mctx, spec.g, p, c[(i + 1) % n]);
  }

  r[pi] = BN_new();

  BN_mod_mul(r[pi], c[pi], spec.priv, order, bctx);
  BN_mod_sub(r[pi], k, r[pi], order, bctx);
  BN_bn2bin(c[0], (unsigned char *)sig);

  for (int i = 0; i < n; i++) {
    EC_POINT_point2oct(spec.g, spec.pubs[i], POINT_CONVERSION_UNCOMPRESSED,
                       (uint8_t *)sig + BN_SIZE + i * POINT_SIZE, POINT_SIZE,
                       NULL);
    BN_bn2bin(r[i],
              (unsigned char *)sig + BN_SIZE + n * POINT_SIZE + i * BN_SIZE);
  }

  for (int i = 0; i < n; i++) {
    BN_free(r[i]);
    BN_free(c[i]);
  }

  BN_free(k);
  free(c);
  free(r);
  EC_POINT_free(p);
  BN_free(order);
  BN_CTX_free(bctx);
  EVP_MD_CTX_free(mctx);
  ringsig_keypair_spec_free(&spec);

  ret = 1;
  return ret;
}

int ringsig_sign_b64(const ringsig_keypair_extern_t *spec, const char *msg,
                     int msg_len, char *sigb64) {
  char *sig = (char *)calloc(sizeof(char), ringsig_sign_len(spec->nr_mem));
  ringsig_sign(spec, msg, msg_len, sig);
  Base64encode(sigb64, sig, ringsig_sign_len(spec->nr_mem));
  free(sig);
  return 1;
}

int ringsig_verify(const char *msg, int msg_len, const char *sig, int sig_len) {

  if (sig_len < ringsig_sign_len(keyset_spec.nr_mem)) return 0; // we only mind if sig_len < real_sig_len

  int n = keyset_spec.nr_mem;
  int ret = 0;

  BIGNUM *c0 = BN_new();
  BIGNUM **r = (BIGNUM **)calloc(sizeof(BIGNUM *), n);

  EC_POINT **points = keyset_spec.pubs;
  EC_POINT *p = EC_POINT_new(keyset_spec.g);

  EVP_MD_CTX *mctx = EVP_MD_CTX_new();
  ringsig_prehash(mctx, msg, msg_len);

  BN_bin2bn((const unsigned char *)sig, BN_SIZE, c0);
  BIGNUM *c = BN_dup(c0);

  for (int i = 0; i < n; i++) {
    r[i] = BN_new();
    BN_bin2bn(
        (const unsigned char *)sig + BN_SIZE + n * POINT_SIZE + i * BN_SIZE,
        BN_SIZE, r[i]);
    EC_POINT_mul(keyset_spec.g, p, r[i], points[i], c, NULL);
    ringsig_hashPOINT2BN(mctx, keyset_spec.g, p, c);
  }

  if (BN_cmp(c, c0) == 0) ret = 1;

  for (int i = 0; i < n; i++) BN_free(r[i]);

  free(r);
  BN_free(c0);
  BN_free(c);
  EC_POINT_free(p);
  EVP_MD_CTX_free(mctx);

  return ret;
}

int ringsig_verify_b64(const char *msg, int msg_len, const char *sigb64) {
  int sig_len = Base64decode_len(sigb64);
  char *sig = (char *)calloc(sizeof(char), sig_len);
  Base64decode(sig, sigb64);
  int ret = ringsig_verify(msg, msg_len, sig, sig_len);
  free(sig);
  return ret;
}

void ringsig_keyset_spec_init(ringsig_keyset_spec_t *spec, int nr_mem) {
  spec->nr_mem = nr_mem;
  spec->privs = (BIGNUM **)calloc(sizeof(BIGNUM *), nr_mem);
  spec->pubs = (EC_POINT **)calloc(sizeof(EC_POINT *), nr_mem);
  spec->g = EC_GROUP_new_by_curve_name(NID_sm2);
  for (int i = 0; i < nr_mem; i++) {
    spec->privs[i] = ringsig_BN_rand();
    spec->pubs[i] = EC_POINT_new(keyset_spec.g);
    EC_POINT_mul(spec->g, spec->pubs[i], spec->privs[i], NULL, NULL, NULL);
  }
}

static void ringsig_keyset_extern_init(const ringsig_keyset_spec_t *spec,
                                       ringsig_keyset_extern_t *ext) {
  ext->nr_mem = spec->nr_mem;
  ext->privs = (char **)calloc(sizeof(char *), spec->nr_mem);
  ext->pubs = (char *)calloc(sizeof(char *),
                             Base64encode_len(spec->nr_mem * POINT_SIZE));
  for (int i = 0; i < spec->nr_mem; i++) {
    ext->privs[i] = (char *)calloc(sizeof(char), Base64encode_len(BN_SIZE));
    ringsig_BN2b64(spec->privs[i], ext->privs[i]);
  }
  ringsig_POINTS2b64(spec->g, (const EC_POINT **)spec->pubs, spec->nr_mem,
                     ext->pubs);
}

void ringsig_keyset_init(int nr_mem) {
  ringsig_keyset_spec_init(&keyset_spec, nr_mem);
  ringsig_keyset_extern_init(&keyset_spec, &keyset_extern);
}

void ringsig_keyset_renew(int nr_mem){
  for (int i = 0; i < keyset_spec.nr_mem; i++){
    EC_POINT_free(keyset_spec.pubs[i]);
    BN_free(keyset_spec.privs[i]);
    free(keyset_extern.privs[i]);
  }

  EC_GROUP_free(keyset_spec.g);
  free(keyset_spec.pubs);
  free(keyset_extern.pubs);
  free(keyset_extern.privs);
  ringsig_keyset_init(nr_mem);
}

ringsig_keypair_extern_t ringsig_keypair_dispatch(int mine) {
  ringsig_keypair_extern_t ext;
  ext.priv = keyset_extern.privs[mine];
  ext.pubs = keyset_extern.pubs;
  ext.nr_mem = keyset_extern.nr_mem;
  ext.mine = mine;
  return ext;
}

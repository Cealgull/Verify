#ifndef __RINGSIG_H
#define __RINGSIG_H

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/bn.h>
#include <openssl/ec.h>
#include <openssl/evp.h>

struct ringsig_keyset_spec {
  BIGNUM **privs;
  EC_POINT **pubs;
  EC_GROUP *g;
  int nr_mem;
};

struct ringsig_keyset_extern {
  char **privs;
  char *pubs;
  int nr_mem;
};

struct ringsig_keypair_extern {
  char *priv;
  char *pubs;
  int nr_mem;
  int mine;
};

struct ringsig_keypair_spec {
  BIGNUM *priv;
  EC_POINT **pubs;
  EC_GROUP *g;
  int nr_mem;
  int mine;
};

typedef struct ringsig_keyset_spec ringsig_keyset_spec_t;
typedef struct ringsig_keyset_extern ringsig_keyset_extern_t;
typedef struct ringsig_keypair_spec ringsig_keypair_spec_t;
typedef struct ringsig_keypair_extern ringsig_keypair_extern_t;

void ringsig_keyset_init(int nr_mem);
void ringsig_keyset_renew(int nr_mem);

int ringsig_sign_len(int nr_mem);
int ringsig_signb64_len(int nr_mem);
int ringsig_sign(const ringsig_keypair_extern_t *spec, const char *msg,
                 int msg_len, char *sig);
int ringsig_sign_b64(const ringsig_keypair_extern_t *spec, const char *msg,
                     int msg_len, char *sigb64);
int ringsig_verify(const char *msg, int msg_len, const char *sig, int sig_len);
int ringsig_verify_b64(const char *msg, int msg_len, const char *sigb64);

ringsig_keypair_extern_t ringsig_keypair_dispatch(int mine);

#ifdef __cplusplus
}
#endif

#endif

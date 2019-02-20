#include <assert.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdalign.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <sodium.h>

#include "emacs-module.h"


#define MAX_MSG_SIZE 4096


/* Frequently-used symbols. */
static emacs_value nil;
static emacs_value list;


int plugin_is_GPL_compatible;


int urandombytes(uint8_t buffer[], unsigned long long size)
{
  int fd;
  fd = open("/dev/urandom", O_RDONLY);
  if(fd < 0) {
    return fd;
  }

  int rc = read(fd, buffer, size);
  if(rc >= 0) {
    close(fd);
  }
  return rc;
}

char* to_hex(char hex[], const uint8_t bin[], size_t length)
{
  size_t i;
  uint8_t *p0 = (uint8_t *)bin;
  char *p1 = hex;

  for( i = 0; i < length; i++ ) {
    snprintf( p1, 3, "%02x", *p0 );
    p0 += 1;
    p1 += 2;
  }

  return hex;
}

uint8_t* from_hex(const char hex[], uint8_t bin[])
{
  size_t length = strlen(hex);
  size_t i, j;
  unsigned int x;

  for( i = 0, j = 0; i < length; i += 2, j++ ) {
    sscanf(&hex[i], "%02x", &x);
    bin[j] = (uint8_t)x;
  }

  return bin;
}

int is_zero(const uint8_t *data, int len)
{
  int i;
  int rc = 0;

  for(i = 0; i < len; ++i) {
    rc |= data[i];
  }

  return rc;
}

int encrypt(uint8_t encrypted[], const uint8_t pk[], const uint8_t sk[], const uint8_t nonce[], const uint8_t plain[], int length)
{
  uint8_t temp_plain[MAX_MSG_SIZE];
  uint8_t temp_encrypted[MAX_MSG_SIZE];
  int rc;

  if (length+crypto_box_ZEROBYTES >= MAX_MSG_SIZE) {
    return -2;
  }

  memset(temp_plain, '\0', crypto_box_ZEROBYTES);
  memcpy(temp_plain + crypto_box_ZEROBYTES, plain, length);

  rc = crypto_box(temp_encrypted, temp_plain, crypto_box_ZEROBYTES + length, nonce, pk, sk);

  if (rc != 0) {
    return -1;
  }

  if (is_zero(temp_plain, crypto_box_BOXZEROBYTES) != 0) {
    return -3;
  }

  memcpy(encrypted, temp_encrypted + crypto_box_BOXZEROBYTES, crypto_box_ZEROBYTES + length);

  return crypto_box_ZEROBYTES + length - crypto_box_BOXZEROBYTES;
}

int decrypt(uint8_t plain[], const uint8_t pk[], const uint8_t sk[], const uint8_t nonce[], const uint8_t encrypted[], int length)
{
  uint8_t temp_encrypted[MAX_MSG_SIZE];
  uint8_t temp_plain[MAX_MSG_SIZE];
  int rc;

  if(length+crypto_box_BOXZEROBYTES >= MAX_MSG_SIZE) {
    return -2;
  }
  memset(temp_encrypted, '\0', crypto_box_BOXZEROBYTES);
  memcpy(temp_encrypted + crypto_box_BOXZEROBYTES, encrypted, length);

  rc = crypto_box_open(temp_plain, temp_encrypted, crypto_box_BOXZEROBYTES + length, nonce, pk, sk);

  if( rc != 0 ) {
    return -1;
  }

  if( is_zero(temp_plain, crypto_box_ZEROBYTES) != 0 ) {
    return -3;
  }

  memcpy(plain, temp_plain + crypto_box_ZEROBYTES, crypto_box_BOXZEROBYTES + length);

  return crypto_box_BOXZEROBYTES + length - crypto_box_ZEROBYTES;
}

static char* copy_string(emacs_env *env, emacs_value v) {
  ptrdiff_t size = 0;
  env->copy_string_contents(env, v, NULL, &size);
  char *s = malloc(size);
  env->copy_string_contents(env, v, s, &size);
  return s;
}

#define SODIUM_BOX_MAKE_NONCE \
  "Return a new nonce."

static emacs_value
box_make_nonce(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)args;
  (void)ptr;

  uint8_t nonce[crypto_box_NONCEBYTES];
  if (urandombytes(nonce, crypto_box_NONCEBYTES) < 0) {
    emacs_value signal = env->intern(env, "file-error");
    char msg[] = "/dev/urandom";
    emacs_value message = env->make_string(env, msg, strlen(msg));
    env->non_local_exit_signal(env, signal, message);
    return nil;
  }
  char hexnonce[2*crypto_box_NONCEBYTES+1];

  to_hex(hexnonce, nonce, crypto_box_NONCEBYTES);

  return env->make_string(env, hexnonce, (ptrdiff_t) strlen(hexnonce));
}

#define SODIUM_BOX_MAKE_KEYPAIR \
  "(sodium-box-make-keypair)\n" \
  "\n" \
  "Return alist with a new public and secret key."

static emacs_value
box_make_keypair(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)args;
  (void)ptr;

  uint8_t public_key[crypto_box_PUBLICKEYBYTES];
  uint8_t secret_key[crypto_box_SECRETKEYBYTES];

  crypto_box_keypair(public_key, secret_key);

  char phexbuf[2*crypto_box_PUBLICKEYBYTES+1];
  char shexbuf[2*crypto_box_SECRETKEYBYTES+1];

  to_hex(phexbuf, public_key, crypto_box_PUBLICKEYBYTES);
  to_hex(shexbuf, secret_key, crypto_box_SECRETKEYBYTES);

  emacs_value cons = env->intern(env, "cons");
  emacs_value pk_key = env->intern(env, "pk");
  emacs_value sk_key = env->intern(env, "sk");
  emacs_value pk = env->make_string(env, phexbuf, (ptrdiff_t) strlen(phexbuf));
  emacs_value sk = env->make_string(env, shexbuf, (ptrdiff_t) strlen(shexbuf));

  emacs_value fun_args[] = {pk_key, pk};
  emacs_value pk_pair = env->funcall(env, cons, 2, fun_args);
  fun_args[0] = sk_key;
  fun_args[1] = sk;
  emacs_value sk_pair = env->funcall(env, cons, 2, fun_args);

  fun_args[0] = pk_pair;
  fun_args[1] = sk_pair;

  return env->funcall(env, list, 2, fun_args);
}

#define SODIUM_BOX_ENCRYPT \
  "(sodium-box-encrypt PK SK NONCE PLAIN)\n" \
  "\n" \
  "Return encrypted text PLAIN with public key PK, secret key SK and NONCE."

static emacs_value
box_encrypt(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)ptr;

  char* pk = copy_string(env, args[0]);
  char* sk = copy_string(env, args[1]);
  char* noncehex = copy_string(env, args[2]);
  char* plain = copy_string(env, args[3]);

  uint8_t encrypted[MAX_MSG_SIZE];
  uint8_t public_key[crypto_box_PUBLICKEYBYTES];
  uint8_t secret_key[crypto_box_SECRETKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  from_hex(pk, public_key);
  from_hex(sk, secret_key);
  from_hex(noncehex, nonce);
  int rc = encrypt(encrypted, public_key, secret_key, nonce, (const uint8_t*)plain, strlen(plain));
  free(pk);
  free(sk);
  free(noncehex);
  free(plain);
  if (rc < 0) {
    return nil;
  }

  char encrypted_hex[MAX_MSG_SIZE];
  to_hex(encrypted_hex, encrypted, rc);


  return env->make_string(env, encrypted_hex, (ptrdiff_t) strlen(encrypted_hex));
}

#define SODIUM_BOX_DECRYPT \
  "(sodium-box-decrypt PK SK NONCE ENCRYPTED)\n" \
  "\n" \
  "Return decrypted text ENCRYPTED with public key PK, secret key SK and NONCE."

static emacs_value
box_decrypt(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)ptr;

  char* pk = copy_string(env, args[0]);
  char* sk = copy_string(env, args[1]);
  char* noncehex = copy_string(env, args[2]);
  char* encstr = copy_string(env, args[3]);
  uint8_t public_key[crypto_box_PUBLICKEYBYTES];
  uint8_t secret_key[crypto_box_SECRETKEYBYTES];
  uint8_t nonce[crypto_box_NONCEBYTES];
  from_hex(pk, public_key);
  from_hex(sk, secret_key);
  from_hex(noncehex, nonce);

  uint8_t encrypted[MAX_MSG_SIZE];
  uint8_t decrypted[MAX_MSG_SIZE];
  from_hex(encstr, encrypted);
  int rc = decrypt(decrypted, public_key, secret_key, nonce, encrypted, strlen((const char*) encrypted));
  free(pk);
  free(sk);
  free(noncehex);
  free(encstr);
  if (rc < 0) {
    return nil;
  }
  decrypted[rc] = '\0';

  return env->make_string(env, (const char*) decrypted, (ptrdiff_t) strlen((const char*) decrypted));
}


/* Bind NAME to FUN.  */
static void
bind_function (emacs_env *env, const char *name, emacs_value Sfun)
{
  emacs_value Qfset = env->intern (env, "fset");
  emacs_value Qsym = env->intern (env, name);
  emacs_value args[] = { Qsym, Sfun };

  env->funcall (env, Qfset, 2, args);
}

/* The actual initialization function.  It’s called in a safe regime where all
   members of env are accessible and nonlocal exits are no longer possible. */
static void initialize_module (emacs_env *env) {
  /* Gather symbols. */
  nil = env->intern(env, "nil");
  list = env->intern(env, "list");

  if (sodium_init() < 0) {
    /* panic! the library couldn't be initialized, it is not safe to use */
    emacs_value signal = env->intern(env, "error");
    char msg[] = "Couldn't initialize libsodium";
    emacs_value err_args[] = {env->make_string(env, msg, strlen(msg))};
    emacs_value message = env->funcall(env, list, 1, err_args);
    env->non_local_exit_signal(env, signal, message);
    return;
  }
  /* Bind functions. */
#define DEFUN(lsym, csym, amin, amax, doc, data) \
    bind_function (env, lsym, \
                   env->make_function (env, amin, amax, csym, doc, data))

  DEFUN ("sodium-box-make-keypair", box_make_keypair, 0, 0, SODIUM_BOX_MAKE_KEYPAIR, NULL);
  DEFUN ("sodium-box-make-nonce", box_make_nonce, 0, 0, SODIUM_BOX_MAKE_NONCE, NULL);
  DEFUN ("sodium-box-encrypt", box_encrypt, 4, 4, SODIUM_BOX_ENCRYPT, NULL);
  DEFUN ("sodium-box-decrypt", box_decrypt, 4, 4, SODIUM_BOX_DECRYPT, NULL);
#undef DEFUN

  /* (provide 'sodium) */
  emacs_value provide = env->intern(env, "provide");
  emacs_value sodium = env->intern(env, "sodium");
  env->funcall(env, provide, 1, &sodium);
}

extern int
emacs_module_init (struct emacs_runtime *ert)
{
  /* Fail if Emacs is too old. */
  assert (ert->size > 0);
  if ((size_t) ert->size < sizeof *ert)
    return 1;
  emacs_env *env = ert->get_environment(ert);
  assert (env->size > 0);
  if ((size_t) env->size < sizeof *env)
    return 2;
  /* Prevent Emacs’s dangerous stack overflow recovery. */
  if (signal (SIGSEGV, SIG_DFL) == SIG_ERR)
    return 3;
  /* From this point on we are reasonably safe and can call the actual
     initialization routine. */
  initialize_module (env);
  /* initialize_module can still use env->non_local_exit_signal to signal
     errors during initialization.  These will cause Emacs to signal even if we
     return 0 here. */
  return 0;
}

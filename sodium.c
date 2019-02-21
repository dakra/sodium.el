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


#define BASE64_VARIANT sodium_base64_VARIANT_ORIGINAL


/* Frequently-used symbols. */
static emacs_value nil;
static emacs_value list;


int plugin_is_GPL_compatible;


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

  unsigned char nonce[crypto_box_NONCEBYTES];
  randombytes_buf(nonce, sizeof(nonce));

  char nonce_b64[sodium_base64_encoded_len(sizeof(nonce), BASE64_VARIANT)];
  sodium_bin2base64(nonce_b64, sizeof(nonce_b64), nonce, sizeof(nonce), BASE64_VARIANT);
  return env->make_string(env, nonce_b64, (ptrdiff_t) strlen(nonce_b64));
}

#define SODIUM_BOX_KEYPAIR \
  "(sodium-box-keypair)\n" \
  "\n" \
  "Return alist with a new public and secret key."

static emacs_value
box_keypair(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)args;
  (void)ptr;

  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  if (crypto_box_keypair(pk, sk) != 0) {
    return nil;
  }

  char pk_b64[sodium_base64_encoded_len(sizeof(pk), BASE64_VARIANT)];
  sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk), BASE64_VARIANT);
  char sk_b64[sodium_base64_encoded_len(sizeof(sk), BASE64_VARIANT)];
  sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, sizeof(sk), BASE64_VARIANT);

  emacs_value cons = env->intern(env, "cons");
  emacs_value pk_key = env->intern(env, "pk");
  emacs_value sk_key = env->intern(env, "sk");
  emacs_value epk = env->make_string(env, pk_b64, (ptrdiff_t) strlen(pk_b64));
  emacs_value esk = env->make_string(env, sk_b64, (ptrdiff_t) strlen(sk_b64));

  emacs_value fun_args[] = {pk_key, epk};
  emacs_value pk_pair = env->funcall(env, cons, 2, fun_args);
  fun_args[0] = sk_key;
  fun_args[1] = esk;
  emacs_value sk_pair = env->funcall(env, cons, 2, fun_args);

  fun_args[0] = pk_pair;
  fun_args[1] = sk_pair;

  return env->funcall(env, list, 2, fun_args);
}

#define SODIUM_BOX_EASY \
  "(sodium-box-easy MSG NONCE PK SK)\n" \
  "\n" \
  "Return encrypted text PLAIN with public key PK, secret key SK and NONCE."

static emacs_value
box_easy(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)ptr;

  char* message = copy_string(env, args[0]);
  char* nonce_b64 = copy_string(env, args[1]);
  char* pk_b64 = copy_string(env, args[2]);
  char* sk_b64 = copy_string(env, args[3]);

  unsigned char ciphertext[crypto_box_MACBYTES + strlen(message)];
  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];

  sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);
  sodium_base642bin(pk, sizeof(pk), pk_b64, strlen(pk_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);
  sodium_base642bin(sk, sizeof(sk), sk_b64, strlen(sk_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);

  if (crypto_box_easy(ciphertext, (unsigned char*) message, strlen(message), nonce, pk, sk) != 0) {
    return nil;
  }
  free(message);
  free(nonce_b64);
  free(pk_b64);
  free(sk_b64);

  char ciphertext_b64[sodium_base64_encoded_len(sizeof(ciphertext), BASE64_VARIANT)];
  sodium_bin2base64(ciphertext_b64, sizeof(ciphertext_b64), ciphertext, sizeof(ciphertext), BASE64_VARIANT);

  return env->make_string(env, ciphertext_b64, (ptrdiff_t) strlen(ciphertext_b64));
}

#define SODIUM_BOX_OPEN_EASY \
  "(sodium-box-open-easy CIPHER NONCE PK SK)\n" \
  "\n" \
  "Return decrypted text ENCRYPTED with public key PK, secret key SK and NONCE."

static emacs_value
box_open_easy(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)ptr;

  char* ciphertext_b64 = copy_string(env, args[0]);
  char* nonce_b64 = copy_string(env, args[1]);
  char* pk_b64 = copy_string(env, args[2]);
  char* sk_b64 = copy_string(env, args[3]);

  unsigned char ciphertext[strlen(ciphertext_b64)];
  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];

  sodium_base642bin(ciphertext, sizeof(ciphertext), ciphertext_b64, strlen(ciphertext_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);
  sodium_base642bin(nonce, sizeof(nonce), nonce_b64, strlen(nonce_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);
  sodium_base642bin(pk, sizeof(pk), pk_b64, strlen(pk_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);
  sodium_base642bin(sk, sizeof(sk), sk_b64, strlen(sk_b64), "\n\r ", NULL, NULL, BASE64_VARIANT);

  unsigned char message[sizeof(ciphertext) - crypto_box_MACBYTES];
  if (crypto_box_open_easy(message, ciphertext, strlen((char *)ciphertext), nonce, pk, sk) != 0) {
    /* message for Bob pretending to be from Alice has been forged! */
    return nil;
  }

  return env->make_string(env, (const char*) message, (ptrdiff_t) strlen((const char*) message));
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

  DEFUN ("sodium-box-keypair", box_keypair, 0, 0, SODIUM_BOX_KEYPAIR, NULL);
  DEFUN ("sodium-box-make-nonce", box_make_nonce, 0, 0, SODIUM_BOX_MAKE_NONCE, NULL);
  DEFUN ("sodium-box-easy", box_easy, 4, 4, SODIUM_BOX_EASY, NULL);
  DEFUN ("sodium-box-open-easy", box_open_easy, 4, 4, SODIUM_BOX_OPEN_EASY, NULL);
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

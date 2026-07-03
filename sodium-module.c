#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "emacs-module.h"


#define BASE64_VARIANT sodium_base64_VARIANT_ORIGINAL

/**
 * Macro that defines a docstring for a function.
 * @param name The function name.
 * @param args The argument list as visible from Emacs (without parens).
 * @param docstring The rest of the documentation.
 */
#define DOCSTRING(name, args, docstring)                                 \
    const char *name##__doc = (docstring "\n\n(fn " args ")")


int plugin_is_GPL_compatible;


/* Signal a `sodium-error' with MSG as error data.
   Returns nil so callers can `return signal_sodium_error (...)';
   the value is ignored by Emacs once a nonlocal exit is pending. */
static emacs_value
signal_sodium_error (emacs_env *env, const char *msg)
{
  emacs_value err_sym = env->intern (env, "sodium-error");
  emacs_value list_fn = env->intern (env, "list");
  emacs_value data = env->make_string (env, msg, (ptrdiff_t) strlen (msg));
  emacs_value payload = env->funcall (env, list_fn, 1, &data);
  env->non_local_exit_signal (env, err_sym, payload);
  return env->intern (env, "nil");
}

/* Copy the contents of the Lisp string V into a fresh NUL-terminated
   buffer and store its length (excluding the NUL) in *LEN_OUT.
   Return NULL if Emacs already signaled an error or allocation failed. */
static char *
copy_string (emacs_env *env, emacs_value v, ptrdiff_t *len_out)
{
  ptrdiff_t size = 0;
  if (!env->copy_string_contents (env, v, NULL, &size))
    return NULL;
  char *s = malloc ((size_t) size);
  if (s == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      return NULL;
    }
  if (!env->copy_string_contents (env, v, s, &size))
    {
      free (s);
      return NULL;
    }
  *len_out = size - 1;
  return s;
}

/* Base64-decode B64 into OUT, which must decode to exactly OUT_SIZE bytes.
   Signal a `sodium-error' mentioning WHAT and return false on
   malformed input or length mismatch. */
static bool
decode_b64_exact (emacs_env *env, const char *b64, unsigned char *out,
                  size_t out_size, const char *what)
{
  size_t decoded_len = 0;
  if (sodium_base642bin (out, out_size, b64, strlen (b64), "\n\r ",
                         &decoded_len, NULL, BASE64_VARIANT) != 0
      || decoded_len != out_size)
    {
      char msg[128];
      snprintf (msg, sizeof msg, "Invalid %s (bad base64 or wrong length)", what);
      signal_sodium_error (env, msg);
      return false;
    }
  return true;
}

DOCSTRING(box_make_nonce, "", "Return a new random nonce as a base64 string.");
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

DOCSTRING(increment, "N",
          "Return increment of the base64-encoded byte sequence N.\n"
          "The increment is little-endian and runs in constant-time for\n"
          "a given length.  `sodium-increment' can be used to increment\n"
          "nonces in constant time.");
static emacs_value
increment(emacs_env *env, ptrdiff_t m, emacs_value *args, void *ptr)
{
  (void)m;
  (void)ptr;

  char *n_b64 = NULL;
  unsigned char *n = NULL;
  char *out_b64 = NULL;
  emacs_value result = NULL;
  ptrdiff_t n_b64_len = 0;
  size_t n_len = 0;

  n_b64 = copy_string (env, args[0], &n_b64_len);
  if (n_b64 == NULL)
    goto cleanup;
  if (n_b64_len == 0)
    {
      signal_sodium_error (env, "Empty input");
      goto cleanup;
    }

  /* Decoded data is always shorter than its base64 encoding. */
  n = malloc ((size_t) n_b64_len);
  if (n == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }

  if (sodium_base642bin (n, (size_t) n_b64_len, n_b64, (size_t) n_b64_len,
                         "\n\r ", &n_len, NULL, BASE64_VARIANT) != 0
      || n_len == 0)
    {
      signal_sodium_error (env, "Invalid base64 input");
      goto cleanup;
    }

  sodium_increment (n, n_len);

  size_t out_size = sodium_base64_encoded_len (n_len, BASE64_VARIANT);
  out_b64 = malloc (out_size);
  if (out_b64 == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }
  sodium_bin2base64 (out_b64, out_size, n, n_len, BASE64_VARIANT);
  result = env->make_string (env, out_b64, (ptrdiff_t) strlen (out_b64));

 cleanup:
  free (n_b64);
  if (n != NULL)
    sodium_memzero (n, (size_t) n_b64_len);
  free (n);
  free (out_b64);
  return result != NULL ? result : env->intern (env, "nil");
}

DOCSTRING(box_keypair, "",
          "Return alist with a new public key `pk' and secret key `sk'.\n"
          "Both keys are base64 strings.");
static emacs_value
box_keypair(emacs_env *env, ptrdiff_t n, emacs_value *args, void *ptr)
{
  (void)n;
  (void)args;
  (void)ptr;

  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES];
  if (crypto_box_keypair(pk, sk) != 0) {
    return signal_sodium_error (env, "crypto_box_keypair failed");
  }

  char pk_b64[sodium_base64_encoded_len(sizeof(pk), BASE64_VARIANT)];
  sodium_bin2base64(pk_b64, sizeof(pk_b64), pk, sizeof(pk), BASE64_VARIANT);
  char sk_b64[sodium_base64_encoded_len(sizeof(sk), BASE64_VARIANT)];
  sodium_bin2base64(sk_b64, sizeof(sk_b64), sk, sizeof(sk), BASE64_VARIANT);
  sodium_memzero (sk, sizeof (sk));

  emacs_value cons = env->intern(env, "cons");
  emacs_value pk_key = env->intern(env, "pk");
  emacs_value sk_key = env->intern(env, "sk");
  emacs_value epk = env->make_string(env, pk_b64, (ptrdiff_t) strlen(pk_b64));
  emacs_value esk = env->make_string(env, sk_b64, (ptrdiff_t) strlen(sk_b64));
  sodium_memzero (sk_b64, sizeof (sk_b64));

  emacs_value fun_args[] = {pk_key, epk};
  emacs_value pk_pair = env->funcall(env, cons, 2, fun_args);
  fun_args[0] = sk_key;
  fun_args[1] = esk;
  emacs_value sk_pair = env->funcall(env, cons, 2, fun_args);

  fun_args[0] = pk_pair;
  fun_args[1] = sk_pair;

  emacs_value list_fn = env->intern(env, "list");
  return env->funcall(env, list_fn, 2, fun_args);
}

DOCSTRING(box, "MSG NONCE PK SK",
          "Encrypt MSG with public key PK, secret key SK and NONCE.\n"
          "NONCE, PK and SK are base64 strings.  Return the base64-encoded\n"
          "ciphertext.  Signal `sodium-error' on invalid input.");
static emacs_value
box(emacs_env *env, ptrdiff_t nargs, emacs_value *args, void *ptr)
{
  (void)nargs;
  (void)ptr;

  char *message = NULL;
  char *nonce_b64 = NULL;
  char *pk_b64 = NULL;
  char *sk_b64 = NULL;
  unsigned char *ciphertext = NULL;
  char *ciphertext_b64 = NULL;
  emacs_value result = NULL;
  ptrdiff_t msg_len = 0;
  ptrdiff_t ignored = 0;

  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES] = {0};

  message = copy_string(env, args[0], &msg_len);
  if (message == NULL)
    goto cleanup;
  nonce_b64 = copy_string(env, args[1], &ignored);
  if (nonce_b64 == NULL)
    goto cleanup;
  pk_b64 = copy_string(env, args[2], &ignored);
  if (pk_b64 == NULL)
    goto cleanup;
  sk_b64 = copy_string(env, args[3], &ignored);
  if (sk_b64 == NULL)
    goto cleanup;

  if (!decode_b64_exact (env, nonce_b64, nonce, sizeof (nonce), "nonce")
      || !decode_b64_exact (env, pk_b64, pk, sizeof (pk), "public key")
      || !decode_b64_exact (env, sk_b64, sk, sizeof (sk), "secret key"))
    goto cleanup;

  size_t cipher_len = crypto_box_MACBYTES + (size_t) msg_len;
  ciphertext = malloc (cipher_len);
  if (ciphertext == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }

  if (crypto_box_easy (ciphertext, (const unsigned char *) message,
                       (size_t) msg_len, nonce, pk, sk) != 0)
    {
      signal_sodium_error (env, "Encryption failed");
      goto cleanup;
    }

  size_t b64_size = sodium_base64_encoded_len (cipher_len, BASE64_VARIANT);
  ciphertext_b64 = malloc (b64_size);
  if (ciphertext_b64 == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }
  sodium_bin2base64 (ciphertext_b64, b64_size, ciphertext, cipher_len, BASE64_VARIANT);

  result = env->make_string (env, ciphertext_b64, (ptrdiff_t) strlen (ciphertext_b64));

 cleanup:
  sodium_memzero (sk, sizeof (sk));
  if (message != NULL)
    sodium_memzero (message, (size_t) msg_len);
  free (message);
  free (nonce_b64);
  free (pk_b64);
  free (sk_b64);
  free (ciphertext);
  free (ciphertext_b64);
  return result != NULL ? result : env->intern (env, "nil");
}

DOCSTRING(box_open, "CIPHER NONCE PK SK",
          "Decrypt CIPHER with public key PK, secret key SK and NONCE.\n"
          "CIPHER, NONCE, PK and SK are base64 strings.  Return the\n"
          "decrypted message.  Signal `sodium-error' on invalid input or\n"
          "when the message is forged or corrupted.");
static emacs_value
box_open(emacs_env *env, ptrdiff_t nargs, emacs_value *args, void *ptr)
{
  (void)nargs;
  (void)ptr;

  char *ciphertext_b64 = NULL;
  char *nonce_b64 = NULL;
  char *pk_b64 = NULL;
  char *sk_b64 = NULL;
  unsigned char *ciphertext = NULL;
  unsigned char *message = NULL;
  emacs_value result = NULL;
  ptrdiff_t ct_b64_len = 0;
  ptrdiff_t ignored = 0;
  size_t cipher_len = 0;
  size_t msg_len = 0;

  unsigned char nonce[crypto_box_NONCEBYTES];
  unsigned char pk[crypto_box_PUBLICKEYBYTES];
  unsigned char sk[crypto_box_SECRETKEYBYTES] = {0};

  ciphertext_b64 = copy_string(env, args[0], &ct_b64_len);
  if (ciphertext_b64 == NULL)
    goto cleanup;
  nonce_b64 = copy_string(env, args[1], &ignored);
  if (nonce_b64 == NULL)
    goto cleanup;
  pk_b64 = copy_string(env, args[2], &ignored);
  if (pk_b64 == NULL)
    goto cleanup;
  sk_b64 = copy_string(env, args[3], &ignored);
  if (sk_b64 == NULL)
    goto cleanup;

  if (ct_b64_len == 0)
    {
      signal_sodium_error (env, "Invalid ciphertext (empty)");
      goto cleanup;
    }

  /* Decoded data is always shorter than its base64 encoding. */
  ciphertext = malloc ((size_t) ct_b64_len);
  if (ciphertext == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }

  if (sodium_base642bin (ciphertext, (size_t) ct_b64_len,
                         ciphertext_b64, (size_t) ct_b64_len,
                         "\n\r ", &cipher_len, NULL, BASE64_VARIANT) != 0)
    {
      signal_sodium_error (env, "Invalid ciphertext (bad base64)");
      goto cleanup;
    }
  if (cipher_len < crypto_box_MACBYTES)
    {
      signal_sodium_error (env, "Invalid ciphertext (too short)");
      goto cleanup;
    }

  if (!decode_b64_exact (env, nonce_b64, nonce, sizeof (nonce), "nonce")
      || !decode_b64_exact (env, pk_b64, pk, sizeof (pk), "public key")
      || !decode_b64_exact (env, sk_b64, sk, sizeof (sk), "secret key"))
    goto cleanup;

  msg_len = cipher_len - crypto_box_MACBYTES;
  message = malloc (msg_len > 0 ? msg_len : 1);
  if (message == NULL)
    {
      signal_sodium_error (env, "Out of memory");
      goto cleanup;
    }

  if (crypto_box_open_easy (message, ciphertext, cipher_len, nonce, pk, sk) != 0)
    {
      signal_sodium_error (env, "Decryption failed (forged or corrupted message?)");
      goto cleanup;
    }

  result = env->make_string (env, (const char *) message, (ptrdiff_t) msg_len);

 cleanup:
  sodium_memzero (sk, sizeof (sk));
  if (message != NULL)
    sodium_memzero (message, msg_len > 0 ? msg_len : 1);
  free (message);
  free (ciphertext);
  free (ciphertext_b64);
  free (nonce_b64);
  free (pk_b64);
  free (sk_b64);
  return result != NULL ? result : env->intern (env, "nil");
}


/* Bind NAME to FUN. */
static void
bind_function (emacs_env *env, const char *name, emacs_value Sfun)
{
  emacs_value Qfset = env->intern (env, "fset");
  emacs_value Qsym = env->intern (env, name);
  emacs_value args[] = { Qsym, Sfun };

  env->funcall (env, Qfset, 2, args);
}

/* Set NAME to integer VALUE. */
static void
set_int (emacs_env *env, const char *name, int value)
{
  emacs_value setq = env->intern (env, "set");
  emacs_value sym = env->intern (env, name);
  emacs_value val = env->make_integer(env, value);
  emacs_value args[] = { sym, val };
  env->funcall (env, setq, 2, args);
}

/* The actual initialization function.  It’s called in a safe regime where all
   members of env are accessible and nonlocal exits are no longer possible. */
static void initialize_module (emacs_env *env) {
  if (sodium_init() < 0) {
    /* panic! the library couldn't be initialized, it is not safe to use */
    emacs_value signal = env->intern(env, "error");
    emacs_value list_fn = env->intern(env, "list");
    char msg[] = "Couldn't initialize libsodium";
    emacs_value err_args[] = {env->make_string(env, msg, strlen(msg))};
    emacs_value message = env->funcall(env, list_fn, 1, err_args);
    env->non_local_exit_signal(env, signal, message);
    return;
  }

  /* (define-error 'sodium-error "libsodium error") */
  emacs_value define_error = env->intern(env, "define-error");
  char err_msg[] = "libsodium error";
  emacs_value def_args[] = {
    env->intern(env, "sodium-error"),
    env->make_string(env, err_msg, strlen(err_msg)),
  };
  env->funcall(env, define_error, 2, def_args);

#define DEFUN(lsym, csym, args) \
    bind_function (env, lsym, \
                   env->make_function (env, args, args, csym, csym##__doc, NULL))

  DEFUN ("sodium-increment",      increment,      1);
  DEFUN ("sodium-box-make-nonce", box_make_nonce, 0);
  DEFUN ("sodium-box-keypair",    box_keypair,    0);
  DEFUN ("sodium-box",            box,            4);
  DEFUN ("sodium-box-open",       box_open,       4);
#undef DEFUN

  set_int(env, "sodium-box-macbytes",       crypto_box_MACBYTES);
  /* Deprecated misnomer, kept for backward compatibility.
     Use `sodium-box-macbytes' instead. */
  set_int(env, "sodium-box-maxbytes",       crypto_box_MACBYTES);
  set_int(env, "sodium-box-noncebytes",     crypto_box_NONCEBYTES);
  set_int(env, "sodium-box-publickeybytes", crypto_box_PUBLICKEYBYTES);
  set_int(env, "sodium-box-secretkeybytes", crypto_box_SECRETKEYBYTES);

  /* (provide 'sodium-module) */
  emacs_value provide = env->intern(env, "provide");
  emacs_value feature = env->intern(env, "sodium-module");
  env->funcall(env, provide, 1, &feature);
}

extern int
emacs_module_init (struct emacs_runtime *ert)
{
  /* Fail if Emacs is too old. */
  if ((size_t) ert->size < sizeof *ert)
    return 1;
  emacs_env *env = ert->get_environment(ert);
  if ((size_t) env->size < sizeof (struct emacs_env_28))
    return 2;
  initialize_module (env);
  /* initialize_module can still use env->non_local_exit_signal to signal
     errors during initialization.  These will cause Emacs to signal even if we
     return 0 here. */
  return 0;
}

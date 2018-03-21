/* libntruencrypt.i */
 %module ntru
 %{
 /* Put header files here or function declarations like below */
 #include "libntruencrypt/randombytes.h"
 #include "libntruencrypt/ntru_crypto.h"
 #include "libntruencrypt/ntru_crypto_ntru_encrypt_param_sets.h"


 extern DRBG_HANDLE drbg;
 extern uint16_t public_key_len;
 extern uint16_t private_key_len;
 extern uint16_t cyphertext_len;
 extern uint16_t plaintext_len;


 extern uint32_t dbrg_randombytes (uint8_t *out, uint32_t num_bytes);
 extern void ntrujs_init ();
 extern ntrujs_public_key_bytes ();
 extern long ntrujs_private_key_bytes ();
 extern long ntrujs_encrypted_bytes ();
 extern long ntrujs_decrypted_bytes ();
 extern long ntrujs_keypair (
 	uint8_t* public_key,
 	uint8_t* private_key
 );
 extern long ntrujs_encrypt (
 	uint8_t* message,
 	long message_len,
 	uint8_t* public_key,
 	uint8_t* cyphertext
 );
 extern long ntrujs_decrypt (
 	uint8_t* cyphertext,
 	uint8_t* private_key,
 	uint8_t* decrypted
 );
 %}

#include "randombytes.h"
 #include "ntru_crypto.h"
 #include "ntru_crypto_ntru_encrypt_param_sets.h"


 extern DRBG_HANDLE drbg;
 extern uint16_t public_key_len;
 extern uint16_t private_key_len;
 extern uint16_t cyphertext_len;
 extern uint16_t plaintext_len;


 extern uint32_t dbrg_randombytes (uint8_t *out, uint32_t num_bytes);
 extern void ntrujs_init ();
 extern ntrujs_public_key_bytes ();
 extern long ntrujs_private_key_bytes ();
 extern long ntrujs_encrypted_bytes ();
 extern long ntrujs_decrypted_bytes ();
 extern long ntrujs_keypair (
 	uint8_t* public_key,
 	uint8_t* private_key
 );
 extern long ntrujs_encrypt (
 	uint8_t* message,
 	long message_len,
 	uint8_t* public_key,
 	uint8_t* cyphertext
 );
 extern long ntrujs_decrypt (
 	uint8_t* cyphertext,
 	uint8_t* private_key,
 	uint8_t* decrypted
 );
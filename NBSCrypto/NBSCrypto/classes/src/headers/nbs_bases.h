//
//	nbs_bases.h
//

#ifndef nbs_bases_h
#define nbs_bases_h


#pragma mark - BASE CONVERT FUNCTIONS
char* basetobase (const char* str, uint8_t a, uint8_t b);
char* basetobasecustom (const char* str, uint8_t a, uint8_t b, const char* charset);


#pragma mark - BASE16 FUNCTIONS
int base16_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen, unsigned int options);
int base16_decode(const char *in, unsigned long inlen, char *out, unsigned long *outlen);


#pragma mark - BASE32 FUNCTIONS
typedef enum {
    BASE32_RFC4648   = 0,
    BASE32_BASE32HEX = 1,
    BASE32_ZBASE32   = 2,
    BASE32_CROCKFORD = 3
} base32_alphabet;
int base32_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen, base32_alphabet id);
int base32_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen, base32_alphabet id);


#pragma mark - BASE64 FUNCTIONS
int base64_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen);
int base64url_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen);
int base64url_strict_encode(const unsigned char *in, unsigned long inlen, char *out, unsigned long *outlen);

int base64_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int base64_strict_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int base64_sane_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int base64url_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int base64url_strict_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);
int base64url_sane_decode(const char *in, unsigned long inlen, unsigned char *out, unsigned long *outlen);


#endif /* nbs_bases_h */

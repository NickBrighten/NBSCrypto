//
//	nbs_misc.h
//

#ifndef nbs_misc_h
#define nbs_misc_h


enum {
    NBSCrypto_OK=0,
    NBSCrypto_ERROR,
};

int mem_neq(const void *a, const void *b, size_t len);
void zeromem(volatile void *out, size_t outlen);
//void copy_or_zeromem(const unsigned char* src, unsigned char* dest, unsigned long len, int coz);

#endif /* nbs_misc_h */

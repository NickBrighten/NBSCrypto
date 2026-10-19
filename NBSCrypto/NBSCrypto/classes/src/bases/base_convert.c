//
//	base_convert.c
//	Based on: https://github.com/phtdacosta/base-utils
//

#include "nbs_crypto.h"


//LOCKUP TABLES
/* Lockup-Table from Base2 to Base63 */
const char _63[] = {
    '0','1','2','3','4','5','6','7','8','9',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '_'
};

/* Lockup-Table for Base64 */
const char _64[] = {
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '0','1','2','3','4','5','6','7','8','9',
    '+','/'
};

const char _94[] = {
    ' ','!','"','#','$','%','&','\'','(', ')','*','+',',','-','.','/',
    '0','1','2','3','4','5','6','7','8','9',
    ':',';','<','=','>','?','@',
    'A','B','C','D','E','F','G','H','I','J','K','L','M','N','O','P','Q','R','S','T','U','V','W','X','Y','Z',
    '[','\\',']','^','_','`',
    'a','b','c','d','e','f','g','h','i','j','k','l','m','n','o','p','q','r','s','t','u','v','w','x','y','z',
    '{','|','}','~'
};
// END LOCKUP TABLES


static inline unsigned short _tbV(const char* a, unsigned char b)
{
    unsigned short i = 0 ;
    while ( *a ) {
	if (*a == b) {
	    return i;
	} else {
	    i++;
	};
    }
    return -1;
}

char* basetobase(const char* str, unsigned char a, unsigned char b)
{
    char* arr = malloc(sizeof(char) * 50);
    char* tmp = arr;
    unsigned long long aux = 0;
    unsigned char len = strlen(str);
    unsigned char lvl = 0;

    bool neg;
    (*str == '-') ? ((void)(neg = true), *str++) : (neg = false);

    while ( *str ) {
	((*str - 0) > 96) ?
	(aux += (9 + ((*str++ - 0) - (96 - 26))) * pow(a, --len)) :
	( ((*str - 0) > 64) ? (aux += (9 + ((*str++ - 0) - 64)) * pow(a, --len)) : (aux += ((*str++ - 0) - 48) * pow(a, --len)) );
    }

    while (aux >= b) {
	++lvl;
	// *arr++ = aux % b;
	// C = A – B * (A / B)
	*arr++ = aux - b * (aux / b);
	aux = aux / b;
    }
    *arr = aux;
    lvl++;

    char* rep = malloc(sizeof(char) * (lvl + 1));
    char* res = rep;
    if (neg) {
	(*rep++ = '-');
	lvl++;
    }

    while (lvl > 0) {
	switch (b) {
	    case 64:{
		*rep++ = _64[tmp[--lvl]];
		break;
	    }
	    default:
		*rep++ = _63[tmp[--lvl]];
		break;
	}
    }
    *rep = '\0';

    if (tmp != NULL) {
	free(tmp);
	tmp = NULL;
    }

    return res;
}

char* basetobasecustom(const char* str, unsigned char a, unsigned char b, const char* charset)
{
    char* arr = malloc(sizeof(char) * 50);
    char* tmp = arr;
    unsigned long long aux = 0;
    unsigned char len = strlen(str);
    unsigned char lvl = 0;

    bool neg;
    (*str == '-') ? ((void)(neg = true), *str++) : (neg = false);


    unsigned short ind;
    while ( *str ) {
	ind = _tbV(charset, *str++);
	if (ind) {
	    aux += ind * pow(a, --len);
	} else {
	    if (arr != NULL) {
		free(arr);
		arr = NULL;
	    }
	    return arr;
	}
    }

    // Successive divisions to find the new numeric representation
    while (aux >= b) {
	++lvl;
	// *arr++ = aux % b;
	// C = A – B * (A / B)
	*arr++ = aux - b * (aux / b);
	aux = aux / b;
    }
    *arr = aux;
    lvl++;

    char* rep = malloc(sizeof(char) * (lvl + 1));
    char* res = rep;
    if (neg) {
	(*rep++ = '-');
	lvl++;
    }

    while (lvl > 0) {
	*rep++ = charset[tmp[--lvl]];
    }
    *rep = '\0';

    if (tmp != NULL) {
	free(tmp);
	tmp = NULL;
    }

    return res;
}

/*
 * main.cpp
 *
 *  Created on: Jul 7, 2015
 *      Author: mahind
 */

#include <iostream>
#include <stdio.h>
#include <math.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <gmp.h>
#include <pbc.h>
#include <assert.h>
#include <openssl/sha.h>

#include "peks.h"


//#define DEBUG 1
/*#ifdef __cplusplus
extern "C" {
        int PEKSOperation(char *W1, char *W2) {
} //function PEKSOperation
} //extern C
#endif*/

int main(int argc, char **argv)
{
	if (argc != 3) {
		printf("Usage: %s <word1> <word2>\n",argv[0]);
        return 1;
    }

	char *W1, *W2;
	W1 = *(++argv);
	W2 = *(++argv);

        /* Order of group G1 and G2 */
	double P;

	/* Apriv = α and Apub = [g, h=g^α] */
	key key;

	/* Trapdoor */
	element_t Tw;

	/* H1(W) */
	element_t H1_W1;

	/* PBC data types */
	pbc_param_t param;
	pairing_t pairing;

	/* Initialize pairing */
	init_pbc_param_pairing(param, pairing);

	/* Get the order of G1 */
	P = mpz_get_d(pairing->r);

#if defined(DEBUG)
	printf("P %lf\n", P);
#endif
	//int nlogP = log2(P);

	/* KeyGen */
	KeyGen(&key, param, pairing);

#if defined(DEBUG)
	element_printf("α %e\n", key.priv);
#endif
	/* H1(W) */
	char *hashedW = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
	sha512(W1, (int)strlen(W1), hashedW);
	element_init_G1(H1_W1, pairing);
	element_from_hash(H1_W1, hashedW, (int)strlen(hashedW));
#if defined(DEBUG)
	element_printf("H1_W1 %B\n", H1_W1);
#endif

	/* Trapdoor */
	Trapdoor(Tw, pairing, key.priv, H1_W1);

	int match;
	match =	Test(W2, (int)strlen(W2), &key.pub, Tw, pairing);

	free(hashedW); hashedW = NULL;
	//free(peks.B); peks.B = NULL;
	pbc_param_clear(param);

        //int match = PEKSOperation(W1, W2);
        if(match)
                printf("Equal\n");
        else
                printf("Not equal\n");

        unsigned char data [1024];
        element_to_bytes(data, key.pub.g);
        std::string *gSerialize;
        std::cout  << "g  " <<key.pub.g << std::endl;
        std::cout  << "Data " << data << std::endl;
        //strcpy(gSerialize, data);
        //printf();
	return 0;
}

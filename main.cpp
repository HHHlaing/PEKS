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
#include <fstream>

#include "peks.h"
#include "base64.hpp"

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
        FILE *fptr;
        fptr = fopen("pairing", "w");
        if (fptr == NULL)
        {
          std::cout << "Error!" << std::endl;
          exit(1);
        }
 	pairing_t pairing;

	/* Initialize pairing */
	init_pbc_param_pairing(param, pairing);
        pbc_param_out_str(fptr, param);
        fclose(fptr);
        std::ifstream in("pairing");
        if (fptr == NULL)
        {
          std::cout << "Error!" << std::endl;
          exit(1);
        }
        std::string line, text;
        while(std::getline(in, line))
        {
          text += line + "\n";
        }
        const char* param_str = text.c_str();
        pbc_param_t param1;
        pbc_param_init_set_str(param1, param_str);
	/* Get the order of G1 */
	P = mpz_get_d(pairing->r);

//#if defined(DEBUG)
	printf("P %lf\n", P);
//#endif
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

	//free(hashedW); hashedW = NULL;
	//free(peks.B); peks.B = NULL;
	//pbc_param_clear(param);

        //int match = PEKSOperation(W1, W2);
        if(match)
                printf("Equal\n");
        else
                printf("Not equal\n");

        match =  TestwithNewParam(W2, (int)strlen(W2), &key.pub, Tw);
        if(match)
                printf("Equal\n");
        else
                printf("Not equal\n");

        int len = element_length_in_bytes(key.pub.g);
        unsigned char g_data [len];
        element_to_bytes(g_data, key.pub.g);
        //element_printf("Original g %B\n", key.pub.g);
        //std::cout  << "Data " << g_data << std::endl;
        //std::string gstr(reinterpret_cast<char*>(g_data));
        std::string g_encoded = base64_encode(g_data, len);
        std::string g_decoded = base64_decode(g_encoded);
        unsigned char* g_array = (unsigned char*)g_decoded.c_str();
        //std::string s( reinterpret_cast<char const*>(data), len ) ;
        //std::cout  << "String " << g_encoded << len << std::endl;
        //std::cout  << "Decode " << g_array << std::endl;

        len = element_length_in_bytes(key.pub.h);
        unsigned char h_data [len];
        element_to_bytes(h_data, key.pub.h);
        //element_printf("Original h %B\n", key.pub.h);
        //std::cout  << "Data " << h_data << std::endl;
        std::string h_encoded = base64_encode(h_data, len);
        std::string h_decoded = base64_decode(h_encoded);
        unsigned char* hstr = (unsigned char*)h_decoded.c_str();
        //std::string s( reinterpret_cast<char const*>(data), len ) ;
        //std::cout  << "String " << h_encoded << len << std::endl;
        //std::cout  << "Decode " << hstr << std::endl;
        //strcpy(gSerialize, data);
        element_t new_g;
        element_t new_h;
        //key1 *key1;
        element_init_G1(new_g, pairing);
        element_init_G1(new_h, pairing);
        //std::cout << "started to converted back" << std::endl;
        int i = element_from_bytes(new_g, g_array);
        //std::cout << "g finished to converted back " << i << std::endl;
        int j = element_from_bytes(new_h, hstr);
        //std::cout << "finished to converted back " << j << std::endl;

        //element_printf("new g %B\n", new_g);
        //element_printf("new h %B\n", new_h);

        element_set(key.pub.g, new_g);
        element_set(key.pub.h, new_h);


	match =	Test(W2, (int)strlen(W2), &key.pub, Tw, pairing);

	free(hashedW); hashedW = NULL;
	//free(peks.B); peks.B = NULL;
	pbc_param_clear(param);

        //int match = PEKSOperation(W1, W2);
        if(match)
                printf("Equal\n");
        else
                printf("Not equal\n");

	return 0;
}

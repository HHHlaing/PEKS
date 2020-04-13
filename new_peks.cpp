#include "new_peks.hpp"
#include <iostream>

peksOpt::peksOpt()
{
    //ctor
}

peksOpt::~peksOpt()
{
    //dtor
}

void peksOpt::sha512(const char *word, int word_size, char hashed_word[SHA512_DIGEST_LENGTH*2+1])
{
	int i;
	unsigned char digest[SHA512_DIGEST_LENGTH];

	SHA512_CTX ctx;
	SHA512_Init(&ctx);
	SHA512_Update(&ctx, word, word_size);
	SHA512_Final(digest, &ctx);

	for (i = 0; i < SHA512_DIGEST_LENGTH; i++)
		sprintf(&hashed_word[i*2], "%02x", (unsigned int)digest[i]);
}


void peksOpt::get_n_bits(char* src, char* out, int bitswanted)
{
	char * ptr = out;
	char byte;
	int i;

	while(bitswanted)
	{
		byte = *src++;
		for(i = 7; i >= 0 && bitswanted > 0 ; i--, bitswanted--)
			*ptr++ = '0' + ((byte >> i) & 0x01);
		if(bitswanted == 0)
			break;
	}
}

void peksOpt::key_printf()
{
	element_printf("α %B\n", priv);
	element_printf("g %B\n", g);
	element_printf("h %B\n", h);
}

void peksOpt::peks_printf()
{
	element_printf("A %B\n", peks);
	printf("B %s\n", B);
}

void peksOpt::init_pbc_param_pairing(pbc_param_t param, pairing_t pairing)
{
	int rbits = 160;
	int qbits = 512;

	/* Generate type A pairing parameters */
	pbc_param_init_a_gen(param, rbits, qbits);

	/* Initialize pairing */
	pairing_init_pbc_param(pairing, param);
#if defined(DEBUG)
	printf("Symmetric %d\n", pairing_is_symmetric(pairing));
#endif
}

void peksOpt::KeyGen(pbc_param_t param, pairing_t pairing)
{
	/* Private key - α */
	element_init_Zr(priv, pairing);
	element_random(priv);

	/* Public key - Apub = [g, h=g^α] */
	element_init_G1(g, pairing);
	element_random(g);
	element_init_G1(h, pairing);
	element_pow_zn(h, g, priv);

}

void peksOpt::PEKS(element_t* g, element_t* h, pairing_t* pairing, element_t* H1_W, int bitswanted)
{
	//char *H2_t = B;
	element_t r, hR, t;

	/* hR = h^r */
	element_init_Zr(r, *pairing);
	element_random(r);
	element_init_G1(hR, *pairing);
	element_pow_zn(hR, *h, r);

	/* t = hasedW1 X hR */
	element_init_GT(t, *pairing);
	pairing_apply(t, *H1_W, hR, *pairing);

	/* gR = g^r */
	element_init_G1(peks, *pairing);
	element_pow_zn(peks, *g, r);

	/* H2(t) */
	char *char_t = (char*)malloc(sizeof(char)*element_length_in_bytes(t));
	char *buffer = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
	element_snprint(char_t, element_length_in_bytes(t), t);
	sha512(char_t, element_length_in_bytes(t), buffer);
	get_n_bits(buffer, B, bitswanted);

	free(char_t); char_t = NULL;
	free(buffer); buffer = NULL;
}

void peksOpt::Trapdoor(pairing_t *pairing, element_t *alpha, element_t *H1_W)
{
	/* H1(W)^α = hashedW1^alpha */
	element_init_G1(Tw, *pairing);
	element_pow_zn(Tw, *H1_W, *alpha);
}

int peksOpt::Test(element_t* g, element_t *h, element_t* peks, char* B, element_t* Tw, pairing_t pairing)
{
	/* PEKS for W2S */

	/* PEKS = [A, B] i.e. A=g^r and B=H2(t) */

        std::cout << std::endl << "%#%#%#%#%#%#%#%%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#" << std::endl;
        element_printf("peks value is >>> %B", *peks);
        std::cout << std::endl << "%#%#%#%#%#%#%#%%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#%#" << std::endl;
	element_t temp,r;

	double P = mpz_get_d(pairing->r);
//#if defined(DEBUG)
	printf("P %lf\n", P);
//#endif
	int nlogP = log2(P);
//#if defined(DEBUG)
	printf("log2(P) %d\n", nlogP);
//#endif

	/* PEKS(key_pub, W2) */
	//B = (char*)malloc(sizeof(char)*(nlogP));
	//std::cout << "B is allocated " << std::endl;
	//PEKS(&peks, pub, pairing, H1_W2, nlogP);
#if defined(DEBUG)
	element_printf("A %B\n", peks.A);
#endif
	element_init_GT(temp, pairing);
	//std::cout << "*peks.first is " << peks->first << std::endl;
	pairing_apply(temp, *Tw, *peks, pairing);
    /* H2(temp) */
	char *char_temp = (char*)malloc(sizeof(char)*element_length_in_bytes(temp));
	char *hashed_temp = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
	element_snprint(char_temp, element_length_in_bytes(temp), temp);
	sha512(char_temp, element_length_in_bytes(temp), hashed_temp);
	char *H2_lhs = (char*)malloc(sizeof(char)*(nlogP));
	get_n_bits(hashed_temp, H2_lhs, nlogP);
    /* Check for equality */
//#if defined(DEBUG)
	int i;
	printf("lhs ");
	for(i = 0; i < nlogP; i++)
		printf("%c", H2_lhs[i]);
	printf("\nrhs ");
	for(i = 0; i < nlogP; i++)
		printf("%c", B[i]);
	printf("\n");
	printf("i is %d ", i);
//#endif
	int match;
	if(!memcmp(H2_lhs, B, nlogP))
		match = 1;
	else
		match = 0;
    /* Free the memory */
	free(H2_lhs); H2_lhs = NULL;
	//free(B); B = NULL;
	free(char_temp); char_temp = NULL;
	free(hashed_temp); hashed_temp = NULL;
	//free(hashedW2); hashedW2 = NULL;

	return match;
}

void peksOpt::set_B(char* addr_B)
{
    B = addr_B;
}

void peksOpt::set_peks(element_t interest_peks)
{
    element_set(peks, interest_peks);
}


void peksOpt::setPubKey(element_t new_g, element_t new_h)
{
    element_set(g, new_g);
    element_printf("\n new new_g is %B \n", g);
    element_set(h, new_h);
    element_printf("\n new new_h is %B \n", h);
}

char *peksOpt::getB()
{
    return B;
}
element_t* peksOpt::getPubg()
{
    return &g;
}

element_t* peksOpt::getPubh()
{
    return &h;
}

element_t* peksOpt::getPriKey()
{
    return &priv;
}

element_t* peksOpt::getTw()
{
    return &Tw;
}

element_t* peksOpt::getPEKS()
{
    return &peks;
}

bool peksOpt::is_empty(std::ifstream& pFile)
{
    return pFile.peek() == std::ifstream::traits_type::eof();
}

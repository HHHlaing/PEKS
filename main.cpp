#include <stdio.h>
#include <iostream>
#include <string>
#include <cstring>

#include "base64.hpp"
#include "new_peks.hpp"
using namespace std;

int main()
{
   peksOpt p_opt;
   pairing_t pairing;
   pbc_param_t param;
   int len;

   element_t H1_W2;
   p_opt.init_pbc_param_pairing(param, pairing);
   double P = mpz_get_d(pairing->r);
   int nlogP = log2(P);
   p_opt.KeyGen(param, pairing);

   char A[] = "hi";
   std::string str_test = "hi";
   char *W2 = &A[0];
   const char *W1 = str_test.c_str();
   int lenW2 = (int)strlen(W2);

   std::cout << "\n before peks generation " << std::endl;

   //std::pair<element_t, char*> peks;
   char *hashedW2 = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
   std::cout << "\n after hashedW2 " << std::endl;
   p_opt.sha512(W2, lenW2, hashedW2);
   std::cout << "\n after  p_opt.sha512(W2, lenW2, hashedW2); " << std::endl;
   element_init_G1(H1_W2, pairing);
   std::cout << "\n after element_init_G1(H1_W2, pairing); " << std::endl;
   element_from_hash(H1_W2, hashedW2, strlen(hashedW2));
   //element_printf("H1_W2 %B\n", H1_W2);


   //char* tmp = malloc(sizeof(char)*(nlogP));
   /* PEKS(key_pub, W2) */
   p_opt.set_B((char*)malloc(sizeof(char)*(nlogP)));
   p_opt.PEKS(p_opt.getPubg(), p_opt.getPubh(), &pairing, &H1_W2, nlogP);

   std::cout << "\n finished peks generation " << std::endl;

   //free(hashedW2); hashedW2 = NULL;

   //get peks and B from object
   element_t* peks;

   char* B;
   peks = p_opt.getPEKS();
   B = p_opt.getB();
   //p_opt.key_printf();

   std::cout << "the original B value is >>>> " << std::endl << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   for(int i = 0; i < nlogP; i++)
      printf("%c", B[i]);
   printf("\n");
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";


   element_t* tw;
   element_t H1_W1;
   /* H1(W) */
   char *hashedW = (char*)malloc(sizeof(char)*SHA512_DIGEST_LENGTH*2+1);
   p_opt.sha512(W1, (int)strlen(W1), hashedW);
   element_init_G1(H1_W1, pairing);
   element_from_hash(H1_W1, hashedW, (int)strlen(hashedW));
   p_opt.Trapdoor(&pairing, p_opt.getPriKey(), &H1_W1);
   tw = p_opt.getTw();

   //free(hashedW); hashedW = NULL;
   //pbc_param_clear(param);


   int match = p_opt.Test(p_opt.getPubg(), p_opt.getPubh(), peks, B, tw, pairing);
   if(match)
     printf("Equal\n");
   else
     printf("Not equal\n");

   //encode pub g
   len = element_length_in_bytes_compressed(*p_opt.getPubg());
   unsigned char *g_data = (unsigned char*)malloc(len);
   element_to_bytes_compressed(g_data, *p_opt.getPubg());
   //element_snprint(&g_data, len, *p_opt.getPubg());
   std::cout << std::endl << "finished element_to_bytes g_data" << std::endl;
   string g_string = base64_encode(g_data, len);
   std::cout << std::endl << "finished base64 encode g" << std::endl;

   //encode pub h
   len = element_length_in_bytes_compressed(*p_opt.getPubh());
   unsigned char *h_data = (unsigned char*)malloc(len);
   element_to_bytes_compressed(h_data, *p_opt.getPubh());
   //element_snprint(&h_data, len, *p_opt.getPubh());
   std::cout << std::endl << "finished element_snprint" << std::endl;
   string h_key_string = base64_encode(h_data, len);
   std::cout << std::endl << "finished base64 encode h" << std::endl;



   std::cout << std::endl << "g_encoded is >>> " << g_string << std::endl;
   std::cout << std::endl << "h_encoded is >>> " << h_key_string << std::endl;


   //decode g and h
   string g_decode_string = base64_decode(g_string);
   string h_decode_string = base64_decode(h_key_string);
  // std::string h_decoded = base64_decode(h_encoded);


   unsigned char* g_array = (unsigned char*)malloc(1024);
   g_array = (unsigned char*)g_decode_string.c_str();
   unsigned char* h_array = (unsigned char*)malloc(1024);
   h_array = (unsigned char*)h_decode_string.c_str();

   element_t new_g;
   element_t new_h;

   element_init_G1(new_g, pairing);
   element_init_G1(new_h, pairing);

   element_from_bytes_compressed(new_g, g_array);
   element_from_bytes_compressed(new_h, h_array);


   element_printf("\ng %B\n", new_g);
   element_printf("\nh %B\n", new_h);
   p_opt.setPubKey(new_g, new_h);
   //done setting transferred key

   p_opt.key_printf();
   match = p_opt.Test(&new_g, &new_h, peks, B, tw, pairing);
   if(match)
     printf("Equal after transferring keys\n");
   else
     printf("Not equal after transferring keys\n");


   //start to encode the peks
   len = element_length_in_bytes_compressed(*peks);
   unsigned char *peks_data = (unsigned char*)malloc(len);
   element_to_bytes_compressed(peks_data, *p_opt.getPEKS());
   //element_snprint(&h_data, len, *p_opt.getPubh());
   string peks_string = base64_encode(peks_data, len);

   string peks_decode_string = base64_decode(peks_string);
  // std::string h_decoded = base64_decode(h_encoded);


   unsigned char* peks_array = (unsigned char*)malloc(1024);
   peks_array = (unsigned char*)peks_decode_string.c_str();

   //start to encode Hr (change to string)
   std::string h_string(B);
   //std::string hr_string = GetHexFromBin(h_string);
   //output of encoded values
   //std::cout << "peks_encoded is " << peks_encoded << std::endl;
   //std::cout << "hr_string_encoded is " << h_string << std::endl;



   //start to decode peks
   //std::string new_peks_decoded = base64_decode(peks_encoded);
   //unsigned char* new_peks_array = (unsigned char*)new_peks_decoded.c_str();

   //creation of new peks
   element_t new_peks;
   element_init_G1(new_peks, pairing);
   element_from_bytes_compressed(new_peks, peks_array);
   p_opt.set_peks(new_peks);

   //creation of new hr (change string to char*)
   //std::string hr_string_Bin_arr = GetBinFromHex(hr_string);
   char *new_B = (char*)h_string.c_str();
   std::cout << std::endl << "new B is " << std::endl;
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   for(int i = 0; i < nlogP; i++)
      printf("%c", new_B[i]);
   printf("\n");
   std::cout << "%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%\n";
   p_opt.set_B(new_B);

   peks = p_opt.getPEKS();
   B = p_opt.getB();


   int count = 0;

   for(int j = 0; j <1; j++)
   {
      match = p_opt.Test(p_opt.getPubg(), p_opt.getPubh(), peks, B, tw, pairing);

      if(match)
      {
        count++;
      }
   }

   std::cout << "equal count is >>> " << count << std::endl;


   return 0;

}

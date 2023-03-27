#include "em_wb_aes_ctr.h"
#include "stdio.h"

int main(int argc, char *argv[]){
  char* pt = argv[1];
  int pt_len = sizeof(argv[1]);

  char ct[1000] = {};
  char iv[1000] = {};

  int ct_len = 0;
  em_wb_aes_ctr_encrypt(pt, pt_len, ct, &ct_len, iv, 1);

  printf("input:%s output: %s\n", pt ,ct);

  em_wb_aes_ctr_decrypt(ct, ct_len, pt, &pt_len, iv, 1);

  printf("encrypted:%s decrypted: %s\n", ct ,pt);

}
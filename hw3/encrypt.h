/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */
#include <openssl/aes.h>

struct ctr_state { 
  unsigned char ivec[16];
  unsigned int num;
  unsigned char ecount[16];
}; 

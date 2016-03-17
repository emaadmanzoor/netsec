/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */

struct ip_header_t { // first 20 bytes
  uint8_t version_headerlen;
  uint8_t dont_care[8];
  uint8_t protocol;
  uint8_t dont_care2[2];
  uint8_t sip[4]; // source ip address
  uint8_t dip[4]; // destination ip address
}__attribute__((__packed__));

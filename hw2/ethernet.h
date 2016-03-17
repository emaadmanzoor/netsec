/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */

struct ethernet_header_t {
  uint8_t dmac[6]; // 6 octets
  uint8_t smac[6]; // 6 octets
  uint8_t ethertype[2]; // 2 octets
}__attribute__((__packed__));

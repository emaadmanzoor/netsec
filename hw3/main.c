/* 
 * Copyright 2016 Emaad Ahmed Manzoor
 * License: Apache License, Version 2.0
 * https://github.com/emaadmanzoor/netsec
 */
#include <arpa/inet.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>

#include "encrypt.h"
#include "param.h"

extern char *optarg;
extern int optind;
static const char optstring[] = "l:k:";
static const char usage[] = "usage: %s [-l port] -k keyfile destination port\n";

int main(int argc, char *argv[]) {
  char c; // for getopt
  int inport;
  int outport;
  char *keyfilename;
  unsigned char key[MAX_KEY_LEN];
  char *dest;
  bool reverse = false;
  FILE *f;
  struct in_addr *addr;
  char destip[BUF_SIZE];

  // codec
  int nbytes;
  char buffer[BUF_SIZE] = {0};
  char inbuffer[BUF_SIZE+8] = {0};
  char encryp[BUF_SIZE] = {0};
  char decryp[BUF_SIZE] = {0};
  char payload[BUF_SIZE+8];
  unsigned char iv[8] = {0};
  struct ctr_state state;
  AES_KEY aes_key;
  
  // socket io
  struct hostent *server;
  struct sockaddr_in serv_addr;
  int sockfd;

  while ((c = getopt(argc, argv, optstring)) != -1) {
    switch (c) {
      case 'l':
        inport = atoi(optarg);
        reverse = true;
        break;
      case 'k':
        keyfilename = optarg;
        break;
      case '?':
        fprintf(stderr, "Invalid argument at pos: %d\n", optind);
        fprintf(stderr, usage, argv[0]);
        exit(-1);
    }
  } 

  dest = argv[argc-2];
  outport = atoi(argv[argc-1]);

  fprintf(stderr, "Starting pbproxy: (");
  if (reverse)
    fprintf(stderr, " Server mode, In-port=%d ", inport);
  fprintf(stderr, " Keyfile=%s ", keyfilename);
  fprintf(stderr, " Dest=%s ", dest);
  fprintf(stderr, " Out-port=%d )\n", outport);

  // read key
  f = fopen(keyfilename, "rb");
  if (f == NULL) {
    fprintf(stderr, "Could not open keyfile: %s\n", keyfilename);
    exit(-1);
  }
  fgets((char*) key, MAX_KEY_LEN, f);

  // convert destination host to ip address
  server = gethostbyname(dest);
  addr = (struct in_addr *) (server->h_addr_list)[0];
  strcpy(destip, inet_ntoa(*addr));

  //fcntl(STDIN_FILENO, F_SETFL, O_NONBLOCK);

  if (reverse == true) {
    // start server    
  } else {
    // start client

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    memset((char *) &serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    memmove((char *)&serv_addr.sin_addr.s_addr,
            (char *)server->h_addr, server->h_length);
    serv_addr.sin_port = htons(outport);

    if (connect(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) {
      printf("Error connecting to destination socket\n");
      printf("Start server with: ncat -e /bin/cat -k -l <port>\n");
      printf("Connect with: ./pbproxy -k mykey localhost <port>\n");
      exit(-1);
    }

    AES_set_encrypt_key(key, 128, &aes_key);

    while (true) {
      // read input into buffer
      while ((nbytes = read(0, buffer, BUF_SIZE)) > 0) {
        printf("\tInput bytes: ");
        for (int i = 0; i < nbytes; i++)
          printf("%02x ", buffer[i]);
        printf("\n");

        // initialisation vector bytes
        RAND_bytes(iv, 8);

        // init ctr
        state.num = 0;
        memset(state.ecount, 0, 16);
        memset(state.ivec + 8, 0, 8);
        memcpy(state.ivec, iv, 8);

        // encrypt
        AES_ctr128_encrypt((unsigned char *) buffer,
                           (unsigned char *) encryp, nbytes,
                           &aes_key, state.ivec, state.ecount,
                           &state.num);
        
        // setup payload
        memset(payload, 0, BUF_SIZE + 8);
        memcpy(payload, iv, 8); // iv is in the first 8 bytes
        memcpy(payload + 8, encryp, nbytes); // the rest is the data

        write(sockfd, payload, nbytes + 8);
       
        printf("\tSent IV (8 bytes): ");
        for (int i = 0; i < 8; i++)
          printf("%02x ", (unsigned char) payload[i]);
        printf("\n");
        
        printf("\tSent encrypted data (%d bytes): ", nbytes);
        for (int i = 0; i < nbytes; i++)
          printf("%02x ", (unsigned char) payload[i+8]);
        printf("\n");

        printf("\tSent %d bytes.\n", nbytes + 8);
      
        printf("\n");

        // give receiver a chance to run
        if (nbytes < BUF_SIZE)
          break;

        /*for (int i = 0; i < nbytes; i++)
          printf("%02x ", (unsigned char) buffer[i]);
        printf("\n");
        
        for (int i = 0; i < nbytes; i++)
          printf("%02x ", (unsigned char) encryp[i]);
        printf("\n");

        for (int i = 0; i < nbytes; i++)
          printf("%02x ", (unsigned char) decryp[i]);
        printf("\n");*/
      }

      // receive data from socket
      while ((nbytes = read(sockfd, inbuffer, BUF_SIZE+8)) > 0) {
        printf("\tReceived %d bytes.\n", nbytes);
        printf("\tIV (8 bytes): ");
        for (int i = 0; i < 8; i++)
          printf("%02x ", (unsigned char) inbuffer[i]);
        printf("\n");

        memcpy(iv, inbuffer, 8); // iv is in first 8 bytes
        
        state.num = 0;
        memset(state.ecount, 0, 16);
        memset(state.ivec + 8, 0, 8);
        memcpy(state.ivec, iv, 8);

        memset(decryp, 0, BUF_SIZE);

        AES_ctr128_encrypt((unsigned char *) inbuffer+8,
                           (unsigned char *) decryp, nbytes-8,
                           &aes_key, state.ivec, state.ecount,
                           &state.num);

        printf("\tDecrypted data (%d bytes): ", nbytes - 8);
        for (int i = 8; i < nbytes; i++)
          printf("%02x ", (unsigned char) inbuffer[i]);
        printf("\n");

        printf("\tDecrypted string: ");
        printf("%.*s\n", nbytes-8, decryp);

        printf("\n");

        // give sender a chance to run
        if (nbytes < BUF_SIZE + 8)
          break;
      }
    }
  } 

  return 0;
}

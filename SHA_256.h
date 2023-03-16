#include<stdint.h>
#include<stdio.h>
#include<string.h>
#include<stdlib.h>
#include<stdint.h>
#include<sys/stat.h>
#include<errno.h>

#define block_size 64


unsigned char *sha_256_data(char *input);
unsigned char *sha_256_file(char *file);
unsigned char *sha_data(char* input);
uint8_t Pre_processing_data(unsigned char *block, char *input, uint32_t *w, uint64_t length, uint64_t *rlength, uint64_t NumberOfBits);
unsigned char *sha_file(char* filename);
uint8_t Pre_processing_file(unsigned char *block, FILE *file, uint32_t *w, uint64_t length, uint64_t *rlength, uint64_t NumberOfBits);
void fill_words(unsigned char *block, uint32_t *w);
void comptation(uint32_t *w, uint32_t *hs);
uint32_t s1(uint32_t W);
uint32_t s0(uint32_t W);
uint32_t S1(uint32_t s);
uint32_t S0(uint32_t s);
uint32_t ch(uint32_t x, uint32_t y, uint32_t z);
uint32_t maj(uint32_t x, uint32_t y, uint32_t z);
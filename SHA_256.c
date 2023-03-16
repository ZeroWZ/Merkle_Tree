#include"SHA_256.h"

// hash a string
unsigned char *sha_256_data(char *input){

	unsigned char *hash = sha_data(input);
	if(hash == NULL)
	{
		printf("Error! hasing failed\n");
		return NULL;
	}

	return hash;
}

// hash a file
unsigned char *sha_256_file(char *file){

	unsigned char *hash = sha_file(file);
	if(hash == NULL)
	{
		return NULL;
	}

	return hash;
}

unsigned char *sha_data(char* input){

	// Length (bytes size) and number of input's bits
	uint64_t length = strlen(input);
	uint64_t NumberOfBits = length*8;

	// Checking for input size limit
	if((0xFFFFFFFFFFFFFFFF / 8) < NumberOfBits)
	{
		printf("Input exceeds size limit of 2'091'752 terabytes");
		return NULL;
	}

	// Declare a block with 512-bit size and schedule array of 32-bit words
	unsigned char block[block_size];
	uint32_t w[block_size];

	// Initialize hash values
	uint32_t hs[] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	// Remainin bytes
	uint64_t rlength = length;

	// Break the input into 512-bit blocks and padding them
	while(Pre_processing_data(block, input, w, length,&rlength, NumberOfBits) == 1)
	{
		// Extend and comptation
		comptation(w, hs);
	}

	comptation(w, hs);

	// Allocate memory for the hash pointer
	unsigned char *hash = (unsigned char *)malloc(32 * sizeof(unsigned char));
	if(hash == NULL){
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}

	// Produce the final hash value
	for(unsigned char i = 0; i < 32; i += 4)
	{
		hash[i]   = (unsigned char)((hs[i/4] >> 24) & 0x000000FF);
		hash[i+1] = (unsigned char)((hs[i/4] >> 16) & 0x000000FF);
		hash[i+2] = (unsigned char)((hs[i/4] >> 8) & 0x000000FF);
		hash[i+3] = (unsigned char)(hs[i/4] & 0x000000FF);
	}

	return hash;
}

uint8_t Pre_processing_data(unsigned char *block, char *input, uint32_t *w, uint64_t length, uint64_t *rlength, uint64_t NumberOfBits)
{
	static unsigned char cant = 0;
	// Zero block and w[]
	memset(block, 0, block_size*sizeof(unsigned char));
	memset(w, 0, block_size*sizeof(unsigned char));

	// Break input into 512-bit blocks and padding it
	for(int i = 0; i < block_size; i++){
		if(*rlength > 0)
		{
			block[i] = input[length - *rlength];
			*rlength = *rlength - 1;
			if(*rlength == 0) // Data ends before the end of the block
			{
				if(i < 63){
					i++;
					block[i] = 128;
					if(i < 56)
					{
						for(int j = 56, v = 0; j < 64; j++, v++)
							block[j] = (NumberOfBits >> (56 - 8*v)) & 0x00000000000000FF;
						fill_words(block, w); // Copy the block into first 16 words w[0..15] of the message schedule array
						return 0;
					}
					else // The block can't hold 64 bits
					{
						cant = 1;
						fill_words(block, w);
						return 1;
					}
				}
				else // Last element of data is the last element on the block
				{
					fill_words(block, w);
					return 1;
				}
			}
		}
		else // There is no data to fill in the block
		{
			if(cant == 0) block[i] = 128;
			for(int j = 56, v = 0; j < 64; j++, v++)
				block[j] = (NumberOfBits >> (56 - 8*v)) & 0x00000000000000FF;
			fill_words(block, w);
			return 0;
		}
	}
	fill_words(block, w);
	return 1;
}

unsigned char *sha_file(char* filename){

	FILE *file = fopen(filename, "rb");
	if(file == NULL)
	{
		printf("Error! Can't open %s\n", filename);
		return NULL;
	}
	// Length (bytes size) and number of input's bits
	uint64_t length;

	struct stat Status;
	stat(filename, &Status);
	length = Status.st_size;

	uint64_t NumberOfBits = length*8;

	// Checking for input size limit
	if((0xFFFFFFFFFFFFFFFF / 8) < NumberOfBits)
	{
		printf("Input exceeds size limit of 2'091'752 terabytes");
		return NULL;
	}

	// Declare a block with 512-bit size and schedule array of 32-bit words
	unsigned char block[block_size];
	uint32_t w[block_size];

	// Initialize hash values
	uint32_t hs[] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

	// Remainin bytes
	uint64_t rlength = length;

	// Break message into 512-bit blocks and padding it
	while(Pre_processing_file(block, file, w, length, &rlength, NumberOfBits) == 1)
	{
		// Extend and comptation
		comptation(w, hs);
	}

	comptation(w, hs);

	// Allocate memory for the hash pointer
	unsigned char *hash = (unsigned char *)malloc(32 * sizeof(unsigned char));
	if(hash == NULL){
		fprintf(stderr, "malloc: %s\n", strerror(errno));
		return NULL;
	}

	// Produce the final hash value
	for(unsigned char i = 0; i < 32; i += 4)
	{
		hash[i]   = (unsigned char)((hs[i/4] >> 24) & 0x000000FF);
		hash[i+1] = (unsigned char)((hs[i/4] >> 16) & 0x000000FF);
		hash[i+2] = (unsigned char)((hs[i/4] >> 8) & 0x000000FF);
		hash[i+3] = (unsigned char)(hs[i/4] & 0x000000FF);
	}

	fclose(file);
	return hash;
}

uint8_t Pre_processing_file(unsigned char *block, FILE *file, uint32_t *w, uint64_t length, uint64_t *rlength, uint64_t NumberOfBits)
{
	static unsigned char cant = 0;
	// Zero block and w[]
	memset(block, 0, block_size*sizeof(unsigned char));
	memset(w, 0, block_size*sizeof(unsigned char));

	// Break input into 512-bit blocks and padding them
	for(int i = 0; i < block_size; i++){
		if(*rlength > 0)
		{
			int bytes = 0;

			if ((bytes = fread(block, sizeof(unsigned char), block_size, file)) != block_size)
			{
				*rlength = *rlength - bytes;
				i = bytes - 1;
			}
			else{
				*rlength = *rlength - block_size;
				fill_words(block, w);
				return 1;
			}
			if(bytes) // Data ends before the end of the block
			{
				if(i < 63){
					i++;
					block[i] = 128;
					if(i < 56)
					{
						for(int j = 56, v = 0; j < 64; j++, v++)
							block[j] = (NumberOfBits >> (56 - 8*v)) & 0x00000000000000FF;
						fill_words(block, w); // copy the block into first 16 words w[0..15] of the message schedule array
						return 0;
					}
					else // The block can't hold 64 bits
					{
						cant = 1;
						fill_words(block, w);
						return 1;
					}
				}
			}
		}
		else // There is no data to fill in the block
		{
			if(cant == 0) block[i] = 128;
			for(int j = 56, v = 0; j < 64; j++, v++)
				block[j] = (NumberOfBits >> (56 - 8*v)) & 0x00000000000000FF;
			fill_words(block, w);
			return 0;
		}
	}
	fill_words(block, w);
	return 1;
}


void fill_words(unsigned char *block, uint32_t *w){
	// Copy the block into first 16 words w[0..15] of the message schedule array
	for(unsigned char i = 0; i < 16; i++){
		for(unsigned char j = 0; j < 4; j++){
			w[i] |= ((uint32_t)block[(i*4)+j] << (8*(3-j)));
		}
	}
}

void comptation(uint32_t *w, uint32_t *hs){
	// Initialize array of round constants
	uint32_t k[64] ={
	   0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	   0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	   0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	   0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	   0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	   0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	   0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	   0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

	// Extend the first 16 words into the remaining 48 words
	for(int i = 16; i < 64; i++){
		w[i] = w[i-16] + s0(w[i-15]) + w[i-7] + s1(w[i-2]);
	}

	uint32_t a, b, c, d, e, f, g, h, temp1, temp2;
	// Initialize working variables to current hash value
	a = hs[0];
	b = hs[1];
	c = hs[2];
	d = hs[3];
	e = hs[4];
	f = hs[5];
	g = hs[6];
	h = hs[7];

	// Compression function main loop
	for(int i = 0; i < 64; i++){
		temp1 = h + S1(e) + ch(e, f, g) + k[i] + w[i];
		temp2 = S0(a) + maj(a, b, c);

		h = g;
		g = f;
		f = e;
		e = d + temp1;
		d = c;
		c = b;
		b = a;
		a = temp1 + temp2;
	}

	// Add the compressed chunk to the current hash value
	hs[0] += a;
	hs[1] += b;
	hs[2] += c;
	hs[3] += d;
	hs[4] += e;
	hs[5] += f;
	hs[6] += g;
	hs[7] += h;
}

uint32_t s0(uint32_t W){
	// s0 = (w[i-15] rightrotate  7) ^ (w[i-15] rightrotate 18) ^ (w[i-15] rightshift  3);
	uint32_t r7, r3, r18;

	r7 = (W >> 7) | (W << 25);
	r18 = (W >> 18) | (W << 14);
	r3 = W >> 3;

	return r7 ^ r18 ^ r3;
}

uint32_t s1(uint32_t W){
	// s1 = (w[i-2] rightrotate 17) ^ (w[i-2] rightrotate 19) ^ (w[i-2] rightshift 10)
	uint32_t r17, r19, r10;

	r17 = (W >> 17) | (W << 15);
	r19 = (W >> 19) | (W << 13);
	r10 = W >> 10;

	return r17 ^ r19 ^ r10;
}

uint32_t S1(uint32_t s){
	// S1 = (e rightrotate 6) ^ (e rightrotate 11) ^ (e rightrotate 25);
	uint32_t r6, r11, r25;

	r6 = (s >> 6) | (s << 26);
	r11 = (s >> 11) | (s << 21);
	r25 = (s >> 25) | (s << 7);

	return r6 ^ r11 ^ r25;
}

uint32_t S0(uint32_t s){
	// S0 = (a rightrotate 2) ^ (a rightrotate 13) ^ (a rightrotate 22);
	uint32_t r2, r13, r22;

	r2 = (s >> 2) | (s << 30);
	r13 = (s >> 13) | (s << 19);
	r22 = (s >> 22) | (s << 10);

	return r2 ^ r13 ^ r22;
}

uint32_t ch(uint32_t x, uint32_t y, uint32_t z){
	return (x & y) ^ ((~x) & z);
}

uint32_t maj(uint32_t x, uint32_t y, uint32_t z){
	return (x & y) ^ (x & z) ^ (y & z);
}

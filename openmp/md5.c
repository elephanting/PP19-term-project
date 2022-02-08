/*
 * Simple MD5 implementation from https://gist.github.com/creationix/4710780
 * Compile with: gcc -o md5 -O3 md5.c
 */
#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <omp.h>

#define NUM_THREADS 5

// leftrotate function definition
#define LEFTROTATE(x, c) (((x) << (c)) | ((x) >> (32 - (c))))
#define ERROR 
 
// Note: All variables are unsigned 32 bit and wrap modulo 2^32 when calculating
// r specifies the per-round shift amounts 
const uint32_t r[] = {
    7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
    5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20, 5,  9, 14, 20,
    4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
    6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
};

// Use binary integer part of the sines of integers (in radians) as constants
// Initialize variables:
const uint32_t k[] = {
    0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
    0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
    0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
    0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
    0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
    0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
    0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
    0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
    0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
    0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
    0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
    0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
    0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
    0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
    0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
    0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
};

void md5(uint8_t *initial_msg, size_t initial_len, uint8_t *hash)
{
    uint8_t msg[56 + 64]; // MD5 message buffer
    uint8_t *p;
    int pad_len = 56; // an 8-byte password is always padded to 56-byte
    uint64_t bits_len;

    // The variables h0 ~ h3 will contain the hash
    uint32_t h0 = 0x67452301;
    uint32_t h1 = 0xefcdab89;
    uint32_t h2 = 0x98badcfe;
    uint32_t h3 = 0x10325476;
 
    // Notice: the input bytes are considered as bits strings,
    // where the first bit is the most significant bit of the byte.

    // Pre-processing: padding with zeros
    //   append "0" bit until message length in bit ≡ 448 (mod 512)
    //   append length mod (2 pow 64) to message
    //
    // Since for HW-SW codesign, the input is a 8-byte password, we always
    //   pad it to 448 bits.
    memset(msg, 0, sizeof(msg)); // initialize the MD5 message buffer to zeros
    memcpy(msg, initial_msg, initial_len);

    // Pre-processing: appending a single bit of "1" to the message. 
    msg[initial_len] = 128;

    bits_len = initial_len*8;             // note, we append the length in bits
    memcpy(msg + pad_len, &bits_len, 8);  // at the end of the buffer

    // Process the message in successive 512-bit chunks:
    // for each 512-bit chunk of message:
    for (int offset = 0; offset < pad_len; offset += (512/8))
    {
        // break chunk into sixteen 32-bit words w[j], 0 ≤ j ≤ 15
        uint32_t *w = (uint32_t *) (msg + offset);

        // Initialize hash value for this chunk:
        uint32_t a = h0;
        uint32_t b = h1;
        uint32_t c = h2;
        uint32_t d = h3;

        // Main loop:
        for(uint32_t i = 0; i < 64; i++)
        {
            uint32_t f, g;

             if (i < 16) {
                f = (b & c) | ((~b) & d);
                g = i;
            } else if (i < 32) {
                f = (d & b) | ((~d) & c);
                g = (5*i + 1) % 16;
            } else if (i < 48) {
                f = b ^ c ^ d;
                g = (3*i + 5) % 16;          
            } else {
                f = c ^ (b | (~d));
                g = (7*i) % 16;
            }

            uint32_t temp = d;
            d = c;
            c = b;
            b = b + LEFTROTATE((a + f + k[i] + w[g]), r[i]);
            a = temp;
        }

        // Add this chunk's hash to the result so far:
        h0 += a;
        h1 += b;
        h2 += c;
        h3 += d;
    }

    // store the output hash
    p = (uint8_t *) &h0;
    hash[ 0] = p[0], hash[ 1] = p[1], hash[ 2] = p[2], hash [ 3] = p[3];
    p = (uint8_t *) &h1;
    hash[ 4] = p[0], hash[ 5] = p[1], hash[ 6] = p[2], hash [ 7] = p[3];
    p = (uint8_t *) &h2;
    hash[ 8] = p[0], hash[ 9] = p[1], hash[10] = p[2], hash [11] = p[3];
    p = (uint8_t *) &h3;
    hash[12] = p[0], hash[13] = p[1], hash[14] = p[2], hash [15] = p[3];
}

int crack(const uint8_t passwd_hash[16]) {
	int pwd=-1;
	uint8_t pattern[9], hash[16];
	#pragma omp parallel for private(pattern, hash)
	for (int idx = 0; idx < 100000000; idx++) {
		if (pwd < 0) {
			snprintf(pattern, 9, "%08d", idx);
			md5(pattern, 8, hash);
			if (!strncmp(hash, passwd_hash, 16)) pwd = idx;
		}
	}
	return pwd;
}

void time_crack(uint8_t hash[16], FILE *pFile) {
	double start, end;
	double diff;
  	start = omp_get_wtime();
	int idx = crack(hash);
	end = omp_get_wtime();
  	diff = end - start; // ms
	if (idx >= 0) {
		if( pFile != NULL) fprintf(pFile, "%5.3f\n", diff);
		printf("The password is %08d. time: %5.3f sec\n", idx, diff);
	}
	else {
		printf("error\n");
		if( pFile != NULL) fprintf(pFile, "error\n");
	}

	fflush(pFile);
}

int main(int argc, char **argv)
{
    uint8_t pattern[9], hash[16];
	uint8_t passwd_hash_0[16] =
	{ 0xE8, 0xCD, 0x09, 0x53, 0xAB, 0xDF, 0xDE, 0x43,
	0x3D, 0xFE, 0xC7, 0xFA, 0xA7, 0x0D, 0xF7, 0xF6 };

	uint8_t passwd_hash_1[16] =
	{ 0xF7, 0x9B, 0xFD, 0xD7, 0x92, 0xF8, 0x34, 0x93,
	0x05, 0x5B, 0x08, 0xDD, 0xF4, 0x22, 0x6D, 0x30 };

	uint8_t passwd_hash_2[16] =
	{ 0xDD, 0x07, 0x20, 0x9B, 0x2F, 0xCE, 0x67, 0x25,
	0x08, 0x5C, 0x11, 0x70, 0x06, 0xCC, 0x3E, 0x0E };

	uint8_t passwd_hash_3[16] =
	{ 0x40, 0xE5, 0xA8, 0xF7, 0xE1, 0x3D, 0x4C, 0x44,
	0x93, 0xC2, 0x7C, 0x1F, 0x28, 0x5A, 0xA0, 0x85 };

	uint8_t passwd_hash_4[16] =
	{ 0xB8, 0x1B, 0x38, 0x4D, 0xD5, 0x60, 0x27, 0xA3,
	0x1D, 0x24, 0xA0, 0x54, 0xC9, 0x30, 0x73, 0x5F };

	uint8_t passwd_hash_5[16] =
	{ 0x38, 0x74, 0xCE, 0x95, 0x5A, 0x38, 0xEC, 0x35,
	0xC4, 0x03, 0x74, 0xD5, 0x5E, 0x58, 0x85, 0x08 };

	uint8_t passwd_hash_6[16] =
	{ 0xF8, 0x2E, 0x96, 0x20, 0x0F, 0xCF, 0x07, 0x8E,
	0x78, 0x3A, 0x90, 0x8A, 0x5C, 0xDD, 0x35, 0x80 };

	uint8_t passwd_hash_7[16] =
	{ 0x17, 0x8C, 0xA4, 0xEC, 0x72, 0x4C, 0x03, 0x31,
	0xA3, 0x14, 0x65, 0xF7, 0xE9, 0x25, 0x66, 0xD9 };

	uint8_t passwd_hash_8[16] =
	{ 0xC0, 0xDC, 0xC7, 0x4F, 0x06, 0x46, 0xC4, 0x1A,
	0x4A, 0xE8, 0x5D, 0x89, 0x52, 0xE6, 0x98, 0x4D };

	uint8_t passwd_hash_9[16] =
	{ 0xBC, 0x71, 0xCC, 0x18, 0xFF, 0x3C, 0x4F, 0xD1,
	0xB7, 0x05, 0xE5, 0x29, 0xA1, 0x88, 0x67, 0xDF };
	clock_t start, end;
	double diff;

	FILE *pFile = NULL;
	pFile = fopen( "openmp.txt","w" );
	for( int thread_num = 5 ; thread_num <= 9 ; ++ thread_num) {
		printf("num of threads: %d\n", thread_num);
		fprintf(pFile, "num of threads: %d\n", thread_num);
		fflush(pFile);
		omp_set_num_threads(thread_num);
		for( int j = 0 ; j < 2 ; ++j) {
			time_crack(passwd_hash_0, pFile);
			time_crack(passwd_hash_1, pFile);
			time_crack(passwd_hash_2, pFile);
			time_crack(passwd_hash_3, pFile);
			time_crack(passwd_hash_4, pFile);
			time_crack(passwd_hash_5, pFile);
			time_crack(passwd_hash_6, pFile);
			time_crack(passwd_hash_7, pFile);
			time_crack(passwd_hash_8, pFile);
			time_crack(passwd_hash_9, pFile);
		}
	}
	fclose(pFile);
	return 0;

  	//////////////////0
  	start = clock();
	uint32_t idx;
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_0, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");
	return 0;

	//////////////////1
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_1, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////2
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_2, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////3
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_3, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////4
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_4, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////5
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_5, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////6
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_6, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////7
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_7, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////8
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_8, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");

	//////////////////9
  	start = clock();
	for (idx = 0; idx < 100000000; idx++) {
	sprintf(pattern, "%08d", idx);
	md5(pattern, 8, hash);
	if (!strncmp(hash, passwd_hash_9, 16)) break;
	}
	end = clock();
  	diff = end - start; // ms
	if (idx < 100000000) printf("The password is %s. time: %5.3f sec\n", pattern, diff / CLOCKS_PER_SEC);
	else printf("error");
    return 0;
}


start = time();
int idx = crack(hash);
end = time();
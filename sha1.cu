#ifndef uint32_t
#define uint32_t unsigned int
#endif


#define H0 0x67452301
#define H1 0xEFCDAB89
#define H2 0x98BADCFE
#define H3 0x10325476
#define H4 0xC3D2E1F0

__device__
uint32_t rotl(uint32_t x, uint32_t n) {
  return (x >> (32 - n)) | (x << n);
}

__device__
uint32_t get_global_id() {
  uint32_t blockId, threadsPerBlock;
  blockId = blockIdx.z * gridDim.x * gridDim.y
          + blockIdx.y * gridDim.x
          + blockIdx.x;
  threadsPerBlock = blockDim.x;
  return threadIdx.x + threadsPerBlock * blockId;
}

__global__ void crypt_kernel(ulong start, uint32_t *prefix, ulong plen, uint32_t mask, uint32_t *match){
  int t;
  uint32_t W[80], rnd, id, A,B,C,D,E,T1,T2;
  uint32_t Ws[16];

  id = get_global_id();

  //if (id == 0) {
  //  printf("%08x\n", start);
  //}

  // brutforce is build up as: prefix | thr_id:04x | <rnd>:04x | start:08x
  for (t = 0; t < plen; ++t) {
    Ws[t] = prefix[t];
  //  printf("%04x", prefix[t]);
  }
  // printf("%04x\n", id);


  T1 = (id & 0xf) | (((id >> 4) & 0xf) << 8) | (((id >> 8) & 0xf) << 16) | (((id >> 12) & 0xf) << 24);
  T2 = (T1 & 0xe0e0e0e);
  T2 = ((((T2 >> 1) & T2) >> 2) | (((T2 >> 2) & T2) >> 1)) & 0x1010101;
  Ws[plen] = T1 + 0x30303030 + T2 * 0x27;

  T1 = (uint)(start >> 32);
  T1 = (T1 & 0xf) | (((T1 >> 4) & 0xf) << 8) | (((T1 >> 8) & 0xf) << 16) | (((T1 >> 12) & 0xf) << 24);
  T2 = (T1 & 0xe0e0e0e);
  T2 = ((((T2 >> 1) & T2) >> 2) | (((T2 >> 2) & T2) >> 1)) & 0x1010101;
  Ws[plen + 2] = T1 + 0x30303030 + T2 * 0x27;

  T1 = (uint)start;
  T1 = (T1 & 0xf) | (((T1 >> 4) & 0xf) << 8) | (((T1 >> 8) & 0xf) << 16) | (((T1 >> 12) & 0xf) << 24);
  T2 = (T1 & 0xe0e0e0e);
  T2 = ((((T2 >> 1) & T2) >> 2) | (((T2 >> 2) & T2) >> 1)) & 0x1010101;
  Ws[plen + 3] = T1 + 0x30303030 + T2 * 0x27;

  Ws[plen + 4] = 0x80000000;

  for (t = plen + 5; t < 15; ++t) {
    Ws[t] = 0;
  }

  Ws[15] = 128 + 32 * plen;
  // preparing buffer done

  /*
  if (id == 0) {
    printf("%016x: ", start);
    for (t = 0; t < 16; ++t) {
      printf("%08x", Ws[t]);
    }
    printf(" - %u\n", Ws[15]);
  }
  */

  for (rnd = 0; rnd < 0x10000; ++rnd) {
    // uint32_t digest[5];

#pragma unroll
    for (t = 0; t < 16; ++t) {
      W[t] = Ws[t];
    }

    T1 = (rnd & 0xf) | (((rnd >> 4) & 0xf) << 8) | (((rnd >> 8) & 0xf) << 16) | (((rnd >> 12) & 0xf) << 24);
    T2 = (T1 & 0xe0e0e0e);
    T2 = ((((T2 >> 1) & T2) >> 2) | (((T2 >> 2) & T2) >> 1)) & 0x1010101;
    W[plen + 1] = T1 + 0x30303030 + T2 * 0x27;

    for (t = 16; t < 80; t++) {
      W[t] = rotl(W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16], 1);
    }

    A = H0;
    B = H1;
    C = H2;
    D = H3;
    E = H4;

    for (t = 0; t < 20; t++) {
      T1 = (B & C) | ((~B) & D);
      T2 = rotl(A, 5) + T1 + E + 0x5A827999 + W[t];
      E = D; D = C; C = rotl(B, 30); B = A; A = T2;
    }

    for (t = 20; t < 40; t++) {
      T1 = B ^ C ^ D;
      T2 = rotl(A, 5) + T1 + E + 0x6ED9EBA1 + W[t];
      E = D; D = C; C = rotl(B, 30); B = A; A = T2;
    }

    for (t = 40; t < 60; t++) {
      T1 = (B & C) | (B & D) | (C & D);
      T2 = rotl(A, 5) + T1 + E + 0x8F1BBCDC + W[t];
      E = D; D = C; C = rotl(B, 30); B = A; A = T2;
    }

    for (t = 60; t < 80; t++) {
      T1 = B ^ C ^ D;
      T2 = rotl(A, 5) + T1 + E + 0xCA62C1D6 + W[t];
      E = D; D = C; C = rotl(B, 30); B = A; A = T2;
    }

    A += H0;

    if ((A & mask) == 0) {
      /*
      for (t = 0; t < 16; ++t) {
        printf("%08x", Ws[t]);
      }
      printf(" - %u\n", Ws[15]);
      */

      match[0] = 1;
      match[1] = id;
      match[2] = rnd;
    }
  }
}
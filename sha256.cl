#ifndef uint32_t
#define uint32_t unsigned int
#endif

#define H0 0x6a09e667
#define H1 0xbb67ae85
#define H2 0x3c6ef372
#define H3 0xa54ff53a
#define H4 0x510e527f
#define H5 0x9b05688c
#define H6 0x1f83d9ab
#define H7 0x5be0cd19


uint rotr(uint x, int n) {
  if (n < 32) return (x >> n) | (x << (32 - n));
  return x;
}

uint ch(uint x, uint y, uint z) {
  return (x & y) ^ (~x & z);
}

uint maj(uint x, uint y, uint z) {
  return (x & y) ^ (x & z) ^ (y & z);
}

uint sigma0(uint x) {
  return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
}

uint sigma1(uint x) {
  return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
}

uint gamma0(uint x) {
  return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
}

uint gamma1(uint x) {
  return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
}

__constant uint K[64]={
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};  

__kernel void sha256_crypt_kernel(ulong start, __global uint *prefix, ulong plen, uint mask, __global uint *match){
  int t, msg_pad;
  uint W[80], temp, rnd, id, A,B,C,D,E,F,G,H,T1,T2;
  uint Ws[16];

  id = get_global_id(0);

  // brutforce is build up as: prefix | thr_id:04x | <rnd>:04x | start:08x
  for (t = 0; t < plen; ++t) {
    Ws[t] = prefix[t];
  //  printf("%04x", prefix[t]);
  }
  //printf("%04x", id);


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
    uint digest[8] = {H0, H1, H2, H3, H4, H5, H6, H7};

#pragma unroll
    for (t = 0; t < 16; ++t) {
      W[t] = Ws[t];
    }

    T1 = (rnd & 0xf) | (((rnd >> 4) & 0xf) << 8) | (((rnd >> 8) & 0xf) << 16) | (((rnd >> 12) & 0xf) << 24);
    T2 = (T1 & 0xe0e0e0e);
    T2 = ((((T2 >> 1) & T2) >> 2) | (((T2 >> 2) & T2) >> 1)) & 0x1010101;
    W[plen + 1] = T1 + 0x30303030 + T2 * 0x27;

    A = digest[0] = H0;
    B = digest[1] = H1;
    C = digest[2] = H2;
    D = digest[3] = H3;
    E = digest[4] = H4;
    F = digest[5] = H5;
    G = digest[6] = H6;
    H = digest[7] = H7;

    for (t = 16; t < 64; t++) {
      W[t] = gamma1(W[t - 2]) + W[t - 7] + gamma0(W[t - 15]) + W[t - 16];
    }

    for (t = 0; t < 64; t++) {
      T1 = H + sigma1(E) + ch(E, F, G) + K[t] + W[t];
      T2 = sigma0(A) + maj(A, B, C);
      H = G; G = F; F = E; E = D + T1; D = C; C = B; B = A; A = T1 + T2;
    }

    digest[0] += A;

    if ((digest[0] & mask) == 0) {
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
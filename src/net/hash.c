/**
 * @file hash.c
 * @author Sebastien Bourdeauducq - 2006 - Initial version
 * @author RedoX <dev@redox.ws> - 2015 - GCC Port, cleanup
 * @date 2015/09/07
 * @brief MD5/SHA1 hash utils
 */
#include <string.h>
#include <stdint.h>

#include "net/hash.h"

/* ===== start - public domain MD5 implementation ===== */

/*
 * This code implements the MD5 message-digest algorithm.
 * The algorithm is due to Ron Rivest.  This code was
 * written by Colin Plumb in 1993, no copyright is claimed.
 * This code is in the public domain; do with it what you wish.
 */

struct MD5_CTX {
	uint32_t buf[4];
	uint32_t bits[2];
	uint8_t in[64];
};

/**
 * @brief Start MD5 accumulation.  Set bit count to 0 and buffer to mysterious
 *        initialization constants.
 *
 * @param [in] ctx  Context pointer
 */
static void MD5Init(struct MD5_CTX *ctx)
{
	ctx->buf[0] = 0x67452301;
	ctx->buf[1] = 0xefcdab89;
	ctx->buf[2] = 0x98badcfe;
	ctx->buf[3] = 0x10325476;

	ctx->bits[0] = 0;
	ctx->bits[1] = 0;
}

static void MD5Transform(uint32_t buf[4], uint32_t in[16]);

/**
 * @brief Update context to reflect the concatenation of another buffer full
 * of bytes.
 *
 * @param [in]  ctx  Context
 * @param [in]  buf  Input buffer
 * @param [in]  len  Length
 */
static void MD5Update(struct MD5_CTX *ctx, const uint8_t *buf, uint32_t len)
{
	uint32_t t;

	/* Update bitcount */

	t = ctx->bits[0];
	if ((ctx->bits[0] = t + ((uint32_t) len << 3)) < t)
		ctx->bits[1]++;     /* Carry from low to high */
	ctx->bits[1] += len >> 29;

	t = (t >> 3) & 0x3f;    /* Bytes already in shsInfo->data */

	/* Handle any leading odd-sized chunks */

	if (t) {
		uint8_t *p = (uint8_t *) ctx->in + t;

		t = 64 - t;
		if (len < t) {
			memcpy(p, buf, len);
			return;
		}
		memcpy(p, buf, t);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += t;
		len -= t;
	}
	/* Process data in 64-byte chunks */

	while (len >= 64) {
		memcpy(ctx->in, buf, 64);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);
		buf += 64;
		len -= 64;
	}

	/* Handle any remaining bytes of data. */

	memcpy(ctx->in, buf, len);
}

/**
 * @brief Final wrapup - pad to 64-byte boundary with the bit pattern
 *        1 0* (64-bit count of bits processed, MSB-first)
 *
 * @param [out] digest  Output
 * @param [in]  ctx     Context
 */
static void MD5Final(uint8_t digest[16], struct MD5_CTX *ctx)
{
	uint32_t count;
	uint8_t *p;

	/* Compute number of bytes mod 64 */
	count = (ctx->bits[0] >> 3) & 0x3F;

	/* Set the first char of padding to 0x80.  This is safe since there is
	always at least one byte free */
	p = ctx->in + count;
	*p++ = 0x80;

	/* Bytes of padding needed to make 64 bytes */
	count = 64 - 1 - count;

	/* Pad out to 56 mod 64 */
	if (count < 8) {
		/* Two lots of padding:  Pad the first block to 64 bytes */
		memset(p, 0, count);
		MD5Transform(ctx->buf, (uint32_t *) ctx->in);

		/* Now fill the next block with 56 bytes */
		memset(ctx->in, 0, 56);
	} else {
		/* Pad block to 56 bytes */
		memset(p, 0, count - 8);
	}

	/* Append length in bits and transform */
	((uint32_t *) ctx->in)[14] = ctx->bits[0];
	((uint32_t *) ctx->in)[15] = ctx->bits[1];

	MD5Transform(ctx->buf, (uint32_t *) ctx->in);
	memcpy(digest, ctx->buf, 16);
}

/* The four core functions - F1 is optimized somewhat */

#define F1(x, y, z) (z ^ (x & (y ^ z)))
#define F2(x, y, z) F1(z, x, y)
#define F3(x, y, z) (x ^ y ^ z)
#define F4(x, y, z) (y ^ (x | ~z))

/* This is the central step in the MD5 algorithm. */
#define MD5STEP(f, w, x, y, z, data, s) \
    ( w += f(x, y, z) + data,  w =( w<<s | w>>(32-s))&0xffffffff,  w += x )

/**
 * @brief The core of the MD5 algorithm.
 *
 * This alters an existing MD5 hash to
 * reflect the addition of 16 longwords of new data.  MD5Update blocks
 * the data and converts bytes into longwords for this routine.
 *
 * @param [out] buf   Work buffer
 * @param [in]  in    Input buffer
 */
static void MD5Transform(uint32_t buf[4], uint32_t in[16])
{
	register uint32_t a, b, c, d;

	a = buf[0];
	b = buf[1];
	c = buf[2];
	d = buf[3];

	MD5STEP(F1, a, b, c, d, in[0] + 0xd76aa478, 7);
	MD5STEP(F1, d, a, b, c, in[1] + 0xe8c7b756, 12);
	MD5STEP(F1, c, d, a, b, in[2] + 0x242070db, 17);
	MD5STEP(F1, b, c, d, a, in[3] + 0xc1bdceee, 22);
	MD5STEP(F1, a, b, c, d, in[4] + 0xf57c0faf, 7);
	MD5STEP(F1, d, a, b, c, in[5] + 0x4787c62a, 12);
	MD5STEP(F1, c, d, a, b, in[6] + 0xa8304613, 17);
	MD5STEP(F1, b, c, d, a, in[7] + 0xfd469501, 22);
	MD5STEP(F1, a, b, c, d, in[8] + 0x698098d8, 7);
	MD5STEP(F1, d, a, b, c, in[9] + 0x8b44f7af, 12);
	MD5STEP(F1, c, d, a, b, in[10] + 0xffff5bb1, 17);
	MD5STEP(F1, b, c, d, a, in[11] + 0x895cd7be, 22);
	MD5STEP(F1, a, b, c, d, in[12] + 0x6b901122, 7);
	MD5STEP(F1, d, a, b, c, in[13] + 0xfd987193, 12);
	MD5STEP(F1, c, d, a, b, in[14] + 0xa679438e, 17);
	MD5STEP(F1, b, c, d, a, in[15] + 0x49b40821, 22);

	MD5STEP(F2, a, b, c, d, in[1] + 0xf61e2562, 5);
	MD5STEP(F2, d, a, b, c, in[6] + 0xc040b340, 9);
	MD5STEP(F2, c, d, a, b, in[11] + 0x265e5a51, 14);
	MD5STEP(F2, b, c, d, a, in[0] + 0xe9b6c7aa, 20);
	MD5STEP(F2, a, b, c, d, in[5] + 0xd62f105d, 5);
	MD5STEP(F2, d, a, b, c, in[10] + 0x02441453, 9);
	MD5STEP(F2, c, d, a, b, in[15] + 0xd8a1e681, 14);
	MD5STEP(F2, b, c, d, a, in[4] + 0xe7d3fbc8, 20);
	MD5STEP(F2, a, b, c, d, in[9] + 0x21e1cde6, 5);
	MD5STEP(F2, d, a, b, c, in[14] + 0xc33707d6, 9);
	MD5STEP(F2, c, d, a, b, in[3] + 0xf4d50d87, 14);
	MD5STEP(F2, b, c, d, a, in[8] + 0x455a14ed, 20);
	MD5STEP(F2, a, b, c, d, in[13] + 0xa9e3e905, 5);
	MD5STEP(F2, d, a, b, c, in[2] + 0xfcefa3f8, 9);
	MD5STEP(F2, c, d, a, b, in[7] + 0x676f02d9, 14);
	MD5STEP(F2, b, c, d, a, in[12] + 0x8d2a4c8a, 20);

	MD5STEP(F3, a, b, c, d, in[5] + 0xfffa3942, 4);
	MD5STEP(F3, d, a, b, c, in[8] + 0x8771f681, 11);
	MD5STEP(F3, c, d, a, b, in[11] + 0x6d9d6122, 16);
	MD5STEP(F3, b, c, d, a, in[14] + 0xfde5380c, 23);
	MD5STEP(F3, a, b, c, d, in[1] + 0xa4beea44, 4);
	MD5STEP(F3, d, a, b, c, in[4] + 0x4bdecfa9, 11);
	MD5STEP(F3, c, d, a, b, in[7] + 0xf6bb4b60, 16);
	MD5STEP(F3, b, c, d, a, in[10] + 0xbebfbc70, 23);
	MD5STEP(F3, a, b, c, d, in[13] + 0x289b7ec6, 4);
	MD5STEP(F3, d, a, b, c, in[0] + 0xeaa127fa, 11);
	MD5STEP(F3, c, d, a, b, in[3] + 0xd4ef3085, 16);
	MD5STEP(F3, b, c, d, a, in[6] + 0x04881d05, 23);
	MD5STEP(F3, a, b, c, d, in[9] + 0xd9d4d039, 4);
	MD5STEP(F3, d, a, b, c, in[12] + 0xe6db99e5, 11);
	MD5STEP(F3, c, d, a, b, in[15] + 0x1fa27cf8, 16);
	MD5STEP(F3, b, c, d, a, in[2] + 0xc4ac5665, 23);

	MD5STEP(F4, a, b, c, d, in[0] + 0xf4292244, 6);
	MD5STEP(F4, d, a, b, c, in[7] + 0x432aff97, 10);
	MD5STEP(F4, c, d, a, b, in[14] + 0xab9423a7, 15);
	MD5STEP(F4, b, c, d, a, in[5] + 0xfc93a039, 21);
	MD5STEP(F4, a, b, c, d, in[12] + 0x655b59c3, 6);
	MD5STEP(F4, d, a, b, c, in[3] + 0x8f0ccc92, 10);
	MD5STEP(F4, c, d, a, b, in[10] + 0xffeff47d, 15);
	MD5STEP(F4, b, c, d, a, in[1] + 0x85845dd1, 21);
	MD5STEP(F4, a, b, c, d, in[8] + 0x6fa87e4f, 6);
	MD5STEP(F4, d, a, b, c, in[15] + 0xfe2ce6e0, 10);
	MD5STEP(F4, c, d, a, b, in[6] + 0xa3014314, 15);
	MD5STEP(F4, b, c, d, a, in[13] + 0x4e0811a1, 21);
	MD5STEP(F4, a, b, c, d, in[4] + 0xf7537e82, 6);
	MD5STEP(F4, d, a, b, c, in[11] + 0xbd3af235, 10);
	MD5STEP(F4, c, d, a, b, in[2] + 0x2ad7d2bb, 15);
	MD5STEP(F4, b, c, d, a, in[9] + 0xeb86d391, 21);

	buf[0] += a;
	buf[1] += b;
	buf[2] += c;
	buf[3] += d;
}

/* ===== end - public domain MD5 implementation ===== */

/**
 * @brief FIXME
 *
 * @param [in]  key       FIXME
 * @param [in]  key_len   Key length
 * @param [in]  data      Data buffer
 * @param [in]  data_len  Data Length
 * @param [out] max       FIXME
 */
void hmac_md5(const uint8_t *key, uint32_t key_len,
              const uint8_t *data, uint32_t data_len,
              uint8_t *mac)
{
	struct MD5_CTX context;
	uint8_t k_ipad[64]; /* inner padding - key XORd with ipad */
	uint8_t k_opad[64]; /* outer padding - key XORd with opad */
	uint8_t tk[16];
	uint16_t i;

	/* if key is longer than 64 bytes, set it to key = MD5(key) */
	if(key_len > 64) {
		MD5Init(&context);
		MD5Update(&context, key, key_len);
		MD5Final(tk, &context);

		key = tk;
		key_len = 16;
	}

	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for(i=0;i<64;i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* perform inner MD5 */
	MD5Init(&context);                   /* init context for 1st pass */
	MD5Update(&context, k_ipad, 64);     /* start with inner pad */
	MD5Update(&context, data, data_len); /* then text of datagram */
	MD5Final(mac, &context);             /* finish up 1st pass */

	/* perform outer MD5 */
	MD5Init(&context);                   /* init context for 2nd pass */
	MD5Update(&context, k_opad, 64);     /* start with outer pad */
	MD5Update(&context, mac, 16);        /* then results of 1st hash */
	MD5Final(mac, &context);             /* finish up 2nd pass */
}

/* ===== begin - public domain SHA1 implementation ===== */

struct SHA_CTX {
	uint32_t H[5];
	uint32_t W[80];
	uint16_t lenW;
	uint32_t sizeHi, sizeLo;
};

/**
 * @brief Initialize the SHA1 context
 *
 * @param [in]  ctx   Context pointer
 */
static void SHAInit(struct SHA_CTX *ctx)
{
	uint16_t i;

	ctx->lenW = 0;
	ctx->sizeHi = ctx->sizeLo = 0;

	/* Initialize H with the magic constants (see FIPS180 for constants) */
	ctx->H[0] = 0x67452301L;
	ctx->H[1] = 0xefcdab89L;
	ctx->H[2] = 0x98badcfeL;
	ctx->H[3] = 0x10325476L;
	ctx->H[4] = 0xc3d2e1f0L;

	for (i = 0; i < 80; i++)
		ctx->W[i] = 0;
}

#define SHA_ROTL(X,n) ((((X) << (n)) | ((X) >> (32-(n)))) & 0xffffffffL)

/**
 * @brief FIXME
 *
 * @param [in]  ctx Context pointer
 */
static void SHAHashBlock(struct SHA_CTX *ctx)
{
	uint16_t t;
	uint32_t A,B,C,D,E,TEMP;

	for (t = 16; t <= 79; t++)
		ctx->W[t] = SHA_ROTL(ctx->W[t-3]^ctx->W[t-8]^ctx->W[t-14]^ctx->W[t-16],1);

	A = ctx->H[0];
	B = ctx->H[1];
	C = ctx->H[2];
	D = ctx->H[3];
	E = ctx->H[4];

	for (t = 0; t <= 19; t++) {
		TEMP = (SHA_ROTL(A,5) + (((C^D)&B)^D)     + E + ctx->W[t] + 0x5a827999L);
		E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
	}
	for (t = 20; t <= 39; t++) {
		TEMP = (SHA_ROTL(A,5) + (B^C^D)           + E + ctx->W[t] + 0x6ed9eba1L);
		E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
	}
	for (t = 40; t <= 59; t++) {
		TEMP = (SHA_ROTL(A,5) + ((B&C)|(D&(B|C))) + E + ctx->W[t] + 0x8f1bbcdcL);
		E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
	}
	for (t = 60; t <= 79; t++) {
		TEMP = (SHA_ROTL(A,5) + (B^C^D)           + E + ctx->W[t] + 0xca62c1d6L);
		E = D; D = C; C = SHA_ROTL(B, 30); B = A; A = TEMP;
	}

	ctx->H[0] += A;
	ctx->H[1] += B;
	ctx->H[2] += C;
	ctx->H[3] += D;
	ctx->H[4] += E;
}

/**
 * @brief Update the Context with new data
 *
 * @param [in]  ctx     Context pointer
 * @param [in]  dataIn  Data buffer
 * @param [in]  len     Data length
 */
static void SHAUpdate(struct SHA_CTX *ctx, const uint8_t *dataIn, uint16_t len)
{
	uint16_t i;

	/* Read the data into W and process blocks as they get full */
	for(i = 0; i < len; i++) {
		ctx->W[ctx->lenW / 4] <<= 8;
		ctx->W[ctx->lenW / 4] |= (uint32_t)dataIn[i];
		if ((++ctx->lenW) % 64 == 0) {
			SHAHashBlock(ctx);
			ctx->lenW = 0;
		}
		ctx->sizeLo += 8;
		ctx->sizeHi += (ctx->sizeLo < 8);
	}
}

/**
 * @brief Compute the SHA1 sum
 *
 * @param [in]  ctx     Context
 * @param [out] hashout SHA1 hash buffer
 */
static void SHAFinal(struct SHA_CTX *ctx, uint8_t hashout[20])
{
	uint8_t pad0x80 = 0x80;
	uint8_t pad0x00 = 0x00;
	uint8_t padlen[8];
	uint16_t i;

	/* Pad with a binary 1 (e.g. 0x80), then zeroes, then length */
	padlen[0] = (uint8_t)((ctx->sizeHi >> 24) & 255);
	padlen[1] = (uint8_t)((ctx->sizeHi >> 16) & 255);
	padlen[2] = (uint8_t)((ctx->sizeHi >> 8) & 255);
	padlen[3] = (uint8_t)((ctx->sizeHi >> 0) & 255);
	padlen[4] = (uint8_t)((ctx->sizeLo >> 24) & 255);
	padlen[5] = (uint8_t)((ctx->sizeLo >> 16) & 255);
	padlen[6] = (uint8_t)((ctx->sizeLo >> 8) & 255);
	padlen[7] = (uint8_t)((ctx->sizeLo >> 0) & 255);
	SHAUpdate(ctx, &pad0x80, 1);
	while (ctx->lenW != 56)
		SHAUpdate(ctx, &pad0x00, 1);
	SHAUpdate(ctx, padlen, 8);

	/* Output hash */
	for (i=0;i<20;i++) {
		hashout[i] = (uint8_t)(ctx->H[i / 4] >> 24);
		ctx->H[i / 4] <<= 8;
	}
}

/* ===== end - public domain SHA1 implementation ===== */

/* ===== begin - SHA256 implementation ===== */

struct SHA256_CTX {
	uint32_t H[8];
	uint32_t W[64];
	uint32_t len;
	uint64_t bitlen;
};

static const uint32_t K[64] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba1, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

#define CH(x, y, z)       ((x & y) ^ (~x & z))
#define MAJ(x, y, z)     ((x & y) ^ (x & z) ^ (y & z))
#define ROTR(x, n)       (((x) >> (n)) | ((x) << (32 - (n))))
#define EP0(x)           (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x)           (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x)          (ROTR(x, 7) ^ ROTR(x, 18) ^ ((x) >> 3))
#define SIG1(x)          (ROTR(x, 17) ^ ROTR(x, 19) ^ ((x) >> 10))

static void SHA256Init(struct SHA256_CTX *ctx)
{
	ctx->H[0] = 0x6a09e667;
	ctx->H[1] = 0xbb67ae85;
	ctx->H[2] = 0x3c6ef372;
	ctx->H[3] = 0xa54ff53a;
	ctx->H[4] = 0x510e527f;
	ctx->H[5] = 0x9b05688c;
	ctx->H[6] = 0x1f83d9ab;
	ctx->H[7] = 0x5be0cd19;
	ctx->len = 0;
	ctx->bitlen = 0;
}

static void SHA256Transform(struct SHA256_CTX *ctx)
{
	uint32_t a, b, c, d, e, f, g, h, t1, t2, m[16];
	uint32_t i;

	for(i = 0; i < 16; i++) {
		m[i] = (ctx->W[i * 4] << 24) | (ctx->W[i * 4 + 1] << 16) |
		       (ctx->W[i * 4 + 2] << 8) | (ctx->W[i * 4 + 3]);
	}

	a = ctx->H[0];
	b = ctx->H[1];
	c = ctx->H[2];
	d = ctx->H[3];
	e = ctx->H[4];
	f = ctx->H[5];
	g = ctx->H[6];
	h = ctx->H[7];

	for(i = 0; i < 64; i++) {
		if(i < 16) {
			t1 = h + EP1(e) + CH(e, f, g) + K[i] + m[i];
		} else {
			t1 = SIG1(m[(i - 2) & 15]) + m[(i - 7) & 15] + SIG0(m[(i - 15) & 15]) + m[(i - 16) & 15];
			m[(i - 2) & 15] = t1;
			t1 += h + EP1(e) + CH(e, f, g) + K[i];
		}

		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->H[0] += a;
	ctx->H[1] += b;
	ctx->H[2] += c;
	ctx->H[3] += d;
	ctx->H[4] += e;
	ctx->H[5] += f;
	ctx->H[6] += g;
	ctx->H[7] += h;
}

static void SHA256Update(struct SHA256_CTX *ctx, const uint8_t *data, uint32_t len)
{
	uint32_t i;

	for(i = 0; i < len; i++) {
		ctx->W[ctx->len & 63] = data[i];
		ctx->len++;

		if((ctx->len & 63) == 0) {
			SHA256Transform(ctx);
		}
		ctx->bitlen += 8;
	}
}

static void SHA256Final(struct SHA256_CTX *ctx, uint8_t *hash)
{
	uint32_t i, pad;

	pad = (ctx->len < 56) ? (56 - ctx->len) : (120 - ctx->len);

	ctx->W[ctx->len & 63] = 0x80;
	for(i = 1; i < pad; i++) {
		ctx->W[(ctx->len + i) & 63] = 0;
	}

	ctx->bitlen += pad * 8;
	for(i = 0; i < 8; i++) {
		ctx->W[63 - i] = (ctx->bitlen >> (i * 8)) & 0xFF;
	}

	SHA256Transform(ctx);

	for(i = 0; i < 8; i++) {
		hash[i * 4] = (ctx->H[i] >> 24) & 0xFF;
		hash[i * 4 + 1] = (ctx->H[i] >> 16) & 0xFF;
		hash[i * 4 + 2] = (ctx->H[i] >> 8) & 0xFF;
		hash[i * 4 + 3] = ctx->H[i] & 0xFF;
	}
}

/**
 * @brief HMAC-SHA256
 */
void hmac_sha256(const uint8_t *key, uint32_t key_len,
                const uint8_t *data, uint32_t data_len,
                uint8_t *mac)
{
	struct SHA256_CTX context;
	uint8_t k_ipad[64];
	uint8_t k_opad[64];
	uint8_t tk[32];
	uint32_t i;

	if(key_len > 64) {
		SHA256Init(&context);
		SHA256Update(&context, key, key_len);
		SHA256Final(&context, tk);
		key = tk;
		key_len = 32;
	}

	memset(k_ipad, 0, 64);
	memset(k_opad, 0, 64);
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	for(i = 0; i < 64; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	SHA256Init(&context);
	SHA256Update(&context, k_ipad, 64);
	SHA256Update(&context, data, data_len);
	SHA256Final(&context, mac);

	SHA256Init(&context);
	SHA256Update(&context, k_opad, 64);
	SHA256Update(&context, mac, 32);
	SHA256Final(&context, mac);
}

/**
 * @brief PBKDF2-SHA256 (simplified for WPA2)
 * @param password Passphrase
 * @param password_len
 * @param salt Salt value
 * @param salt_len
 * @param iterations 4096 typical
 * @param output Output buffer (32 bytes)
 */
void pbkdf2_sha256(const uint8_t *password, uint32_t password_len,
                 const uint8_t *salt, uint32_t salt_len,
                 uint32_t iterations,
                 uint8_t *output)
{
	uint8_t U[32];
	uint8_t salt_block[64];
	uint32_t i;

	memcpy(salt_block, salt, salt_len);
	salt_block[salt_len] = 0;
	salt_block[salt_len + 1] = 0;
	salt_block[salt_len + 2] = 0;
	salt_block[salt_len + 3] = 1;

	hmac_sha256(password, password_len, salt_block, salt_len + 4, U);
	memcpy(output, U, 32);

	for(i = 1; i < iterations; i++) {
		hmac_sha256(password, password_len, U, 32, U);
		output[0] ^= U[0];
		output[1] ^= U[1];
		output[2] ^= U[2];
		output[3] ^= U[3];
		output[4] ^= U[4];
		output[5] ^= U[5];
		output[6] ^= U[6];
		output[7] ^= U[7];
		output[8] ^= U[8];
		output[9] ^= U[9];
		output[10] ^= U[10];
		output[11] ^= U[11];
		output[12] ^= U[12];
		output[13] ^= U[13];
		output[14] ^= U[14];
		output[15] ^= U[15];
		output[16] ^= U[16];
		output[17] ^= U[17];
		output[18] ^= U[18];
		output[19] ^= U[19];
		output[20] ^= U[20];
		output[21] ^= U[21];
		output[22] ^= U[22];
		output[23] ^= U[23];
		output[24] ^= U[24];
		output[25] ^= U[25];
		output[26] ^= U[26];
		output[27] ^= U[27];
		output[28] ^= U[28];
		output[29] ^= U[29];
		output[30] ^= U[30];
		output[31] ^= U[31];
	}
}

/* ===== end - SHA256 implementation ===== */

/**
 * @brief FIXME
 *
 * @param [in]  key       FIXME
 * @param [in]  key_len   Key length
 * @param [in]  data      Data buffer
 * @param [in]  data_len  Data Length
 * @param [out] max       FIXME
 */
void hmac_sha1(const uint8_t *key, uint32_t key_len,
               const uint8_t *data, uint32_t data_len,
               uint8_t *mac)
{
	struct SHA_CTX context;
	uint8_t k_ipad[64]; /* inner padding - key XORd with ipad */
	uint8_t k_opad[64]; /* outer padding - key XORd with opad */
	uint8_t tk[20];
	int i;

	if(key_len > 64) {
		SHAInit(&context);
		SHAUpdate(&context, key, key_len);
		SHAFinal(&context, tk);

		key = tk;
		key_len = 20;
	}

	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);

	/* XOR key with ipad and opad values */
	for(i=0;i<64;i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* perform inner SHA1 */
	SHAInit(&context);			/* init context for 1st pass */
	SHAUpdate(&context, k_ipad, 64);	/* start with inner pad */
	SHAUpdate(&context, data, data_len);	/* then text of datagram */
	SHAFinal(&context, mac);		/* finish up 1st pass */

	/* perform outer SHA1 */
	SHAInit(&context);			/* init context for 2nd pass */
	SHAUpdate(&context, k_opad, 64);	/* start with outer pad */
	SHAUpdate(&context, mac, 20);		/* then results of 1st hash */
	SHAFinal(&context, mac);		/* finish up 2nd pass */
}

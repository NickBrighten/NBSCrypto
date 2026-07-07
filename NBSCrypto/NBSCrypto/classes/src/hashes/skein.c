//
//	skein.c
//	Authors / Developers		: Bruce Schneier, Niels Ferguson, Stefan Lucks, Doug Whiting,
//					  Mihir Bellare, Tadayoshi Kohno, Jon Callas and Jesse Walker
//	Last Modified (Original)	: 2008
//

#include "nbs_crypto.h"


#pragma mark DESCRIPTOR
const struct hash_descriptor skein_224_desc =
{
    "skein-224",
    10430224,
    28,
    128,
    &skein_224_init,
    &skein_process,
    &skein_done,
    NULL
};

const struct hash_descriptor skein_256_desc =
{
    "skein-256",
    10430256,
    32,
    128,
    &skein_256_init,
    &skein_process,
    &skein_done,
    NULL
};

const struct hash_descriptor skein_384_desc =
{
    "skein-384",
    10430384,
    48,
    128,
    &skein_384_init,
    &skein_process,
    &skein_done,
    NULL
};

const struct hash_descriptor skein_512_desc =
{
    "skein-512",
    10430512,
    64,
    128,
    &skein_512_init,
    &skein_process,
    &skein_done,
    NULL
};

const struct hash_descriptor skein_1024_desc =
{
    "skein-1024",
    10431024,
    128,
    128,
    &skein_1024_init,
    &skein_process,
    &skein_done,
    NULL
};




#pragma mark - DEFINES

#define  SKEIN_MODIFIER_WORDS  ( 2)

#define  SKEIN_256_STATE_WORDS ( 4)
#define  SKEIN_512_STATE_WORDS ( 8)
#define  SKEIN1024_STATE_WORDS (16)
#define  SKEIN_MAX_STATE_WORDS (16)

#define  SKEIN_256_STATE_BYTES ( 8*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_STATE_BYTES ( 8*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_STATE_BYTES ( 8*SKEIN1024_STATE_WORDS)

#define  SKEIN_256_STATE_BITS  (64*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_STATE_BITS  (64*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_STATE_BITS  (64*SKEIN1024_STATE_WORDS)

#define  SKEIN_256_BLOCK_BYTES ( 8*SKEIN_256_STATE_WORDS)
#define  SKEIN_512_BLOCK_BYTES ( 8*SKEIN_512_STATE_WORDS)
#define  SKEIN1024_BLOCK_BYTES ( 8*SKEIN1024_STATE_WORDS)

#define SKEIN_T1_BIT(BIT)       ((BIT) - 64)

#define SKEIN_T1_POS_TREE_LVL   SKEIN_T1_BIT(112)
#define SKEIN_T1_POS_BIT_PAD    SKEIN_T1_BIT(119)
#define SKEIN_T1_POS_BLK_TYPE   SKEIN_T1_BIT(120)
#define SKEIN_T1_POS_FIRST      SKEIN_T1_BIT(126)
#define SKEIN_T1_POS_FINAL      SKEIN_T1_BIT(127)

#define SKEIN_T1_FLAG_FIRST     (((unsigned long long)  1 ) << SKEIN_T1_POS_FIRST)
#define SKEIN_T1_FLAG_FINAL     (((unsigned long long)  1 ) << SKEIN_T1_POS_FINAL)
#define SKEIN_T1_FLAG_BIT_PAD   (((unsigned long long)  1 ) << SKEIN_T1_POS_BIT_PAD)

#define SKEIN_T1_TREE_LVL_MASK  (((unsigned long long)0x7F) << SKEIN_T1_POS_TREE_LVL)
#define SKEIN_T1_TREE_LEVEL(n)  (((unsigned long long) (n)) << SKEIN_T1_POS_TREE_LVL)

#define SKEIN_BLK_TYPE_KEY      ( 0)
#define SKEIN_BLK_TYPE_CFG      ( 4)
#define SKEIN_BLK_TYPE_PERS     ( 8)
#define SKEIN_BLK_TYPE_PK       (12)
#define SKEIN_BLK_TYPE_KDF      (16)
#define SKEIN_BLK_TYPE_NONCE    (20)
#define SKEIN_BLK_TYPE_MSG      (48)
#define SKEIN_BLK_TYPE_OUT      (63)
#define SKEIN_BLK_TYPE_MASK     (63)

#define SKEIN_T1_BLK_TYPE(T)   (((unsigned long long) (SKEIN_BLK_TYPE_##T)) << SKEIN_T1_POS_BLK_TYPE)
#define SKEIN_T1_BLK_TYPE_KEY   SKEIN_T1_BLK_TYPE(KEY)
#define SKEIN_T1_BLK_TYPE_CFG   SKEIN_T1_BLK_TYPE(CFG)
#define SKEIN_T1_BLK_TYPE_PERS  SKEIN_T1_BLK_TYPE(PERS)
#define SKEIN_T1_BLK_TYPE_PK    SKEIN_T1_BLK_TYPE(PK)
#define SKEIN_T1_BLK_TYPE_KDF   SKEIN_T1_BLK_TYPE(KDF)
#define SKEIN_T1_BLK_TYPE_NONCE SKEIN_T1_BLK_TYPE(NONCE)
#define SKEIN_T1_BLK_TYPE_MSG   SKEIN_T1_BLK_TYPE(MSG)
#define SKEIN_T1_BLK_TYPE_OUT   SKEIN_T1_BLK_TYPE(OUT)
#define SKEIN_T1_BLK_TYPE_MASK  SKEIN_T1_BLK_TYPE(MASK)

#define SKEIN_T1_BLK_TYPE_CFG_FINAL	(SKEIN_T1_BLK_TYPE_CFG | SKEIN_T1_FLAG_FINAL)
#define SKEIN_T1_BLK_TYPE_OUT_FINAL	(SKEIN_T1_BLK_TYPE_OUT | SKEIN_T1_FLAG_FINAL)

#define SKEIN_VERSION           (1)

#ifndef SKEIN_ID_STRING_LE
#define SKEIN_ID_STRING_LE      (0x33414853)
#endif

#define SKEIN_MK_64(hi32,lo32)  ((lo32) + (((unsigned long long) (hi32)) << 32))
#define SKEIN_SCHEMA_VER        SKEIN_MK_64(SKEIN_VERSION,SKEIN_ID_STRING_LE)
#define SKEIN_KS_PARITY         SKEIN_MK_64(0x1BD11BDA,0xA9FC1A22)

#define SKEIN_CFG_STR_LEN       (4*8)

#define SKEIN_CFG_TREE_LEAF_SIZE_POS	( 0)
#define SKEIN_CFG_TREE_NODE_SIZE_POS	( 8)
#define SKEIN_CFG_TREE_MAX_LEVEL_POS	(16)

#define SKEIN_CFG_TREE_LEAF_SIZE_MSK	(((unsigned long long) 0xFF) << SKEIN_CFG_TREE_LEAF_SIZE_POS)
#define SKEIN_CFG_TREE_NODE_SIZE_MSK	(((unsigned long long) 0xFF) << SKEIN_CFG_TREE_NODE_SIZE_POS)
#define SKEIN_CFG_TREE_MAX_LEVEL_MSK	(((unsigned long long) 0xFF) << SKEIN_CFG_TREE_MAX_LEVEL_POS)

#define SKEIN_CFG_TREE_INFO(leaf,node,maxLvl)					\
    (	(((unsigned long long)(leaf  )) << SKEIN_CFG_TREE_LEAF_SIZE_POS) |	\
	(((unsigned long long)(node  )) << SKEIN_CFG_TREE_NODE_SIZE_POS) |	\
	(((unsigned long long)(maxLvl)) << SKEIN_CFG_TREE_MAX_LEVEL_POS) )

#define SKEIN_CFG_TREE_INFO_SEQUENTIAL SKEIN_CFG_TREE_INFO(0,0,0)

#define Skein_Get_Tweak(ctxPtr,TWK_NUM)		((ctxPtr)->h.T[TWK_NUM])
#define Skein_Set_Tweak(ctxPtr,TWK_NUM,tVal)	{(ctxPtr)->h.T[TWK_NUM] = (tVal);}

#define Skein_Get_T0(ctxPtr)	Skein_Get_Tweak(ctxPtr,0)
#define Skein_Get_T1(ctxPtr)	Skein_Get_Tweak(ctxPtr,1)
#define Skein_Set_T0(ctxPtr,T0)	Skein_Set_Tweak(ctxPtr,0,T0)
#define Skein_Set_T1(ctxPtr,T1)	Skein_Set_Tweak(ctxPtr,1,T1)

#define Skein_Set_T0_T1(ctxPtr,T0,T1)	\
{					\
    Skein_Set_T0(ctxPtr,(T0));		\
    Skein_Set_T1(ctxPtr,(T1));		\
}

#define Skein_Set_Type(ctxPtr,BLK_TYPE) Skein_Set_T1(ctxPtr,SKEIN_T1_BLK_TYPE_##BLK_TYPE)
#define Skein_Start_New_Type(ctxPtr,BLK_TYPE){ Skein_Set_T0_T1(ctxPtr,0,SKEIN_T1_FLAG_FIRST | SKEIN_T1_BLK_TYPE_##BLK_TYPE); (ctxPtr)->h.bCnt=0;}

#define Skein_Clear_First_Flag(hdr){(hdr).T[1] &= ~SKEIN_T1_FLAG_FIRST;}
#define Skein_Set_Bit_Pad_Flag(hdr){(hdr).T[1] |=  SKEIN_T1_FLAG_BIT_PAD;}

#define Skein_Set_Tree_Level(hdr,height) {(hdr).T[1] |= SKEIN_T1_TREE_LEVEL(height);}

#ifndef SKEIN_ROUNDS
#define SKEIN_256_ROUNDS_TOTAL (72)
#define SKEIN_512_ROUNDS_TOTAL (72)
#define SKEIN1024_ROUNDS_TOTAL (80)
#else
#define SKEIN_256_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS/100) + 5) % 10) + 5))
#define SKEIN_512_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS/ 10) + 5) % 10) + 5))
#define SKEIN1024_ROUNDS_TOTAL (8*((((SKEIN_ROUNDS    ) + 5) % 10) + 5))
#endif

#define SKEIN_256_NIST_MAX_HASHBITS (256)
#define SKEIN_512_NIST_MAX_HASHBITS (512)

#define BLK_BITS    (WCNT*64)

#define InjectKey(r)			\
    for (i=0;i < WCNT;i++)		\
	X[i] += ks[((r)+i) % (WCNT+1)];	\
	X[WCNT-3] += ts[((r)+0) % 3];	\
	X[WCNT-2] += ts[((r)+1) % 3];	\
	X[WCNT-1] += (r);		\


enum
{
    R_256_0_0=14, R_256_0_1=16,
    R_256_1_0=52, R_256_1_1=57,
    R_256_2_0=23, R_256_2_1=40,
    R_256_3_0= 5, R_256_3_1=37,
    R_256_4_0=25, R_256_4_1=33,
    R_256_5_0=46, R_256_5_1=12,
    R_256_6_0=58, R_256_6_1=22,
    R_256_7_0=32, R_256_7_1=32,

    R_512_0_0=46, R_512_0_1=36, R_512_0_2=19, R_512_0_3=37,
    R_512_1_0=33, R_512_1_1=27, R_512_1_2=14, R_512_1_3=42,
    R_512_2_0=17, R_512_2_1=49, R_512_2_2=36, R_512_2_3=39,
    R_512_3_0=44, R_512_3_1= 9, R_512_3_2=54, R_512_3_3=56,
    R_512_4_0=39, R_512_4_1=30, R_512_4_2=34, R_512_4_3=24,
    R_512_5_0=13, R_512_5_1=50, R_512_5_2=10, R_512_5_3=17,
    R_512_6_0=25, R_512_6_1=29, R_512_6_2=39, R_512_6_3=43,
    R_512_7_0= 8, R_512_7_1=35, R_512_7_2=56, R_512_7_3=22,

    R1024_0_0=24, R1024_0_1=13, R1024_0_2= 8, R1024_0_3=47, R1024_0_4= 8, R1024_0_5=17, R1024_0_6=22, R1024_0_7=37,
    R1024_1_0=38, R1024_1_1=19, R1024_1_2=10, R1024_1_3=55, R1024_1_4=49, R1024_1_5=18, R1024_1_6=23, R1024_1_7=52,
    R1024_2_0=33, R1024_2_1= 4, R1024_2_2=51, R1024_2_3=13, R1024_2_4=34, R1024_2_5=41, R1024_2_6=59, R1024_2_7=17,
    R1024_3_0= 5, R1024_3_1=20, R1024_3_2=48, R1024_3_3=41, R1024_3_4=47, R1024_3_5=28, R1024_3_6=16, R1024_3_7=25,
    R1024_4_0=41, R1024_4_1= 9, R1024_4_2=37, R1024_4_3=31, R1024_4_4=12, R1024_4_5=47, R1024_4_6=44, R1024_4_7=30,
    R1024_5_0=16, R1024_5_1=34, R1024_5_2=56, R1024_5_3=51, R1024_5_4= 4, R1024_5_5=53, R1024_5_6=42, R1024_5_7=41,
    R1024_6_0=31, R1024_6_1=44, R1024_6_2=47, R1024_6_3=46, R1024_6_4=19, R1024_6_5=42, R1024_6_6=44, R1024_6_7=25,
    R1024_7_0= 9, R1024_7_1=48, R1024_7_2=35, R1024_7_3=52, R1024_7_4=23, R1024_7_5=31, R1024_7_6=37, R1024_7_7=20
};




#pragma mark - INLINE

static inline unsigned long long _RotL_64(unsigned long long x, unsigned int N)
{
    return (x << (N & 63)) | (x >> ((64-N) & 63));
}

static inline unsigned long long _skein_swap64(unsigned long long w64)
{
    static const unsigned long long ONE = 1;

    if (1 == ((unsigned char *) & ONE)[0])
	return w64;
    else
	return  (( w64       & 0xFF) << 56) |
	(((w64 >> 8) & 0xFF) << 48) |
	(((w64 >>16) & 0xFF) << 40) |
	(((w64 >>24) & 0xFF) << 32) |
	(((w64 >>32) & 0xFF) << 24) |
	(((w64 >>40) & 0xFF) << 16) |
	(((w64 >>48) & 0xFF) <<  8) |
	(((w64 >>56) & 0xFF)      ) ;
}

static inline void _skein_Put64_LSB_First(unsigned char *dst, const unsigned long long *src, size_t bCnt)
{
    size_t n;

    for (n=0;n<bCnt;n++)
	dst[n] = (unsigned char) (src[n>>3] >> (8*(n&7)));
}

static inline void _skein_Get64_LSB_First(unsigned long long *dst, const unsigned char *src, size_t wCnt)
{
    size_t n;

    for (n=0;n<8*wCnt;n+=8)
	dst[n/8] = (((unsigned long long) src[n  ])      ) +
	(((unsigned long long) src[n+1]) <<  8) +
	(((unsigned long long) src[n+2]) << 16) +
	(((unsigned long long) src[n+3]) << 24) +
	(((unsigned long long) src[n+4]) << 32) +
	(((unsigned long long) src[n+5]) << 40) +
	(((unsigned long long) src[n+6]) << 48) +
	(((unsigned long long) src[n+7]) << 56) ;
}

static inline void _skein256_process(Skein_256_Ctxt_t *ctx,const unsigned char *blkPtr,size_t blkCnt,size_t byteCntAdd)
{
    enum
    {
	WCNT     = SKEIN_256_STATE_WORDS
    };
    size_t i,r;
    unsigned long long ts[3];
    unsigned long long ks[WCNT+1];
    unsigned long long X [WCNT];
    unsigned long long w [WCNT];

    do  {
	ctx->h.T[0] += byteCntAdd;

	ks[WCNT] = SKEIN_KS_PARITY;
	for (i=0;i < WCNT; i++){
	    ks[i]     = ctx->X[i];
	    ks[WCNT] ^= ctx->X[i];
	}
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	ts[2] = ts[0] ^ ts[1];

	_skein_Get64_LSB_First(w, blkPtr, WCNT);

	for (i=0;i < WCNT; i++){
	    X[i]  = w[i] + ks[i];
	}
	X[WCNT-3] += ts[0];
	X[WCNT-2] += ts[1];

	for (r=1;r <= SKEIN_256_ROUNDS_TOTAL/8; r++){
	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_256_0_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_256_0_1); X[3] ^= X[2];

	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_256_1_0); X[3] ^= X[0];
	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_256_1_1); X[1] ^= X[2];

	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_256_2_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_256_2_1); X[3] ^= X[2];

	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_256_3_0); X[3] ^= X[0];
	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_256_3_1); X[1] ^= X[2];
	    InjectKey(2*r-1);

	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_256_4_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_256_4_1); X[3] ^= X[2];

	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_256_5_0); X[3] ^= X[0];
	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_256_5_1); X[1] ^= X[2];

	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_256_6_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_256_6_1); X[3] ^= X[2];

	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_256_7_0); X[3] ^= X[0];
	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_256_7_1); X[1] ^= X[2];
	    InjectKey(2*r);
	}

	for (i=0;i < WCNT;i++)
	    ctx->X[i] = X[i] ^ w[i];

	Skein_Clear_First_Flag(ctx->h);
	blkPtr += SKEIN_256_BLOCK_BYTES;
    }
    while (--blkCnt);
}

static inline int _skein256_init(Skein_256_Ctxt_t *ctx, size_t hashBitLen)
{
    union
    {
	unsigned char b[SKEIN_256_STATE_BYTES];
	unsigned long long w[SKEIN_256_STATE_WORDS];
    } cfg;

    ctx->h.hashBitLen = hashBitLen;
    Skein_Start_New_Type(ctx, CFG_FINAL);

    memset(&cfg.w, 0, sizeof(cfg.w));
    cfg.w[0] = _skein_swap64(SKEIN_SCHEMA_VER);
    cfg.w[1] = _skein_swap64(hashBitLen);
    cfg.w[2] = _skein_swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);

    memset(ctx->X, 0, sizeof(ctx->X));
    _skein256_process(ctx, cfg.b, 1, SKEIN_CFG_STR_LEN);

    Skein_Start_New_Type(ctx, MSG);

    return NBSCrypto_OK;
}

static inline int _skein256_update(Skein_256_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt)
{
    size_t n;

    if (msgByteCnt + ctx->h.bCnt > SKEIN_256_BLOCK_BYTES){
	if (ctx->h.bCnt){
	    n = SKEIN_256_BLOCK_BYTES - ctx->h.bCnt;
	    if (n){
		memcpy(&ctx->b[ctx->h.bCnt],msg,n);
		msgByteCnt  -= n;
		msg         += n;
		ctx->h.bCnt += n;
	    }
	    _skein256_process(ctx,ctx->b,1,SKEIN_256_BLOCK_BYTES);
	    ctx->h.bCnt = 0;
	}
	if (msgByteCnt > SKEIN_256_BLOCK_BYTES){
	    n = (msgByteCnt-1) / SKEIN_256_BLOCK_BYTES;
	    _skein256_process(ctx,msg,n,SKEIN_256_BLOCK_BYTES);
	    msgByteCnt -= n * SKEIN_256_BLOCK_BYTES;
	    msg        += n * SKEIN_256_BLOCK_BYTES;
	}
    }

    if (msgByteCnt){
	memcpy(&ctx->b[ctx->h.bCnt],msg,msgByteCnt);
	ctx->h.bCnt += msgByteCnt;
    }

    return NBSCrypto_OK;
}

static inline int _skein256_final(Skein_256_Ctxt_t *ctx, unsigned char *hashVal)
{
    size_t i,n,byteCnt;
    unsigned long long X[SKEIN_256_STATE_WORDS];

    ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL;
    if (ctx->h.bCnt < SKEIN_256_BLOCK_BYTES)
	memset(&ctx->b[ctx->h.bCnt],0,SKEIN_256_BLOCK_BYTES - ctx->h.bCnt);

    _skein256_process(ctx, ctx->b, 1, ctx->h.bCnt);

    byteCnt = (ctx->h.hashBitLen + 7) >> 3;

    memset(ctx->b, 0, sizeof(ctx->b));
    memcpy(X, ctx->X, sizeof(X));

    for (i=0;i*SKEIN_256_BLOCK_BYTES < byteCnt;i++){
	((unsigned long long *)ctx->b)[0] = _skein_swap64((unsigned long long)i);
	Skein_Start_New_Type(ctx,OUT_FINAL);
	_skein256_process(ctx, ctx->b, 1, sizeof(unsigned long long));
	n = byteCnt - i*SKEIN_256_BLOCK_BYTES;
	if (n >= SKEIN_256_BLOCK_BYTES)
	    n  = SKEIN_256_BLOCK_BYTES;

	_skein_Put64_LSB_First(hashVal+i*SKEIN_256_BLOCK_BYTES, ctx->X, n);
	memcpy(ctx->X, X, sizeof(X));
    }

    return NBSCrypto_OK;
}

static inline void _skein512_process(Skein_512_Ctxt_t *ctx, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd)
{
    enum
    {
	WCNT = SKEIN_512_STATE_WORDS
    };

    size_t i,r;
    unsigned long long ts[3];
    unsigned long long ks[WCNT+1];
    unsigned long long X [WCNT];
    unsigned long long w [WCNT];

    do  {
	ctx->h.T[0] += byteCntAdd;

	ks[WCNT] = SKEIN_KS_PARITY;
	for (i=0;i < WCNT; i++){
	    ks[i]     = ctx->X[i];
	    ks[WCNT] ^= ctx->X[i];
	}
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	ts[2] = ts[0] ^ ts[1];

	_skein_Get64_LSB_First(w, blkPtr, WCNT);

	for (i=0;i < WCNT; i++){
	    X[i]  = w[i] + ks[i];
	}
	X[WCNT-3] += ts[0];
	X[WCNT-2] += ts[1];

	for (r=1;r <= SKEIN_512_ROUNDS_TOTAL/8; r++){
	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_512_0_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_512_0_1); X[3] ^= X[2];
	    X[4] += X[5]; X[5] = _RotL_64(X[5],R_512_0_2); X[5] ^= X[4];
	    X[6] += X[7]; X[7] = _RotL_64(X[7],R_512_0_3); X[7] ^= X[6];

	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_512_1_0); X[1] ^= X[2];
	    X[4] += X[7]; X[7] = _RotL_64(X[7],R_512_1_1); X[7] ^= X[4];
	    X[6] += X[5]; X[5] = _RotL_64(X[5],R_512_1_2); X[5] ^= X[6];
	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_512_1_3); X[3] ^= X[0];

	    X[4] += X[1]; X[1] = _RotL_64(X[1],R_512_2_0); X[1] ^= X[4];
	    X[6] += X[3]; X[3] = _RotL_64(X[3],R_512_2_1); X[3] ^= X[6];
	    X[0] += X[5]; X[5] = _RotL_64(X[5],R_512_2_2); X[5] ^= X[0];
	    X[2] += X[7]; X[7] = _RotL_64(X[7],R_512_2_3); X[7] ^= X[2];

	    X[6] += X[1]; X[1] = _RotL_64(X[1],R_512_3_0); X[1] ^= X[6];
	    X[0] += X[7]; X[7] = _RotL_64(X[7],R_512_3_1); X[7] ^= X[0];
	    X[2] += X[5]; X[5] = _RotL_64(X[5],R_512_3_2); X[5] ^= X[2];
	    X[4] += X[3]; X[3] = _RotL_64(X[3],R_512_3_3); X[3] ^= X[4];
	    InjectKey(2*r-1);

	    X[0] += X[1]; X[1] = _RotL_64(X[1],R_512_4_0); X[1] ^= X[0];
	    X[2] += X[3]; X[3] = _RotL_64(X[3],R_512_4_1); X[3] ^= X[2];
	    X[4] += X[5]; X[5] = _RotL_64(X[5],R_512_4_2); X[5] ^= X[4];
	    X[6] += X[7]; X[7] = _RotL_64(X[7],R_512_4_3); X[7] ^= X[6];

	    X[2] += X[1]; X[1] = _RotL_64(X[1],R_512_5_0); X[1] ^= X[2];
	    X[4] += X[7]; X[7] = _RotL_64(X[7],R_512_5_1); X[7] ^= X[4];
	    X[6] += X[5]; X[5] = _RotL_64(X[5],R_512_5_2); X[5] ^= X[6];
	    X[0] += X[3]; X[3] = _RotL_64(X[3],R_512_5_3); X[3] ^= X[0];

	    X[4] += X[1]; X[1] = _RotL_64(X[1],R_512_6_0); X[1] ^= X[4];
	    X[6] += X[3]; X[3] = _RotL_64(X[3],R_512_6_1); X[3] ^= X[6];
	    X[0] += X[5]; X[5] = _RotL_64(X[5],R_512_6_2); X[5] ^= X[0];
	    X[2] += X[7]; X[7] = _RotL_64(X[7],R_512_6_3); X[7] ^= X[2];

	    X[6] += X[1]; X[1] = _RotL_64(X[1],R_512_7_0); X[1] ^= X[6];
	    X[0] += X[7]; X[7] = _RotL_64(X[7],R_512_7_1); X[7] ^= X[0];
	    X[2] += X[5]; X[5] = _RotL_64(X[5],R_512_7_2); X[5] ^= X[2];
	    X[4] += X[3]; X[3] = _RotL_64(X[3],R_512_7_3); X[3] ^= X[4];
	    InjectKey(2*r);
	}

	for (i=0;i < WCNT;i++)
	    ctx->X[i] = X[i] ^ w[i];

	Skein_Clear_First_Flag(ctx->h);
	blkPtr += SKEIN_512_BLOCK_BYTES;
    }
    while (--blkCnt);
}

static inline int _skein512_init(Skein_512_Ctxt_t *ctx, size_t hashBitLen)
{
    union
    {
	unsigned char b[SKEIN_512_STATE_BYTES];
	unsigned long long w[SKEIN_512_STATE_WORDS];
    } cfg;

    ctx->h.hashBitLen = hashBitLen;
    Skein_Start_New_Type(ctx, CFG_FINAL);

    memset(&cfg.w, 0, sizeof(cfg.w));
    cfg.w[0] = _skein_swap64(SKEIN_SCHEMA_VER);
    cfg.w[1] = _skein_swap64(hashBitLen);
    cfg.w[2] = _skein_swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);

    memset(ctx->X, 0, sizeof(ctx->X));
    _skein512_process(ctx, cfg.b, 1, SKEIN_CFG_STR_LEN);
    Skein_Start_New_Type(ctx,MSG);

    return NBSCrypto_OK;
}

static inline int _skein512_update(Skein_512_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt)
{
    size_t n;

    if (msgByteCnt + ctx->h.bCnt > SKEIN_512_BLOCK_BYTES){
	if (ctx->h.bCnt){
	    n = SKEIN_512_BLOCK_BYTES - ctx->h.bCnt;
	    if (n){
		memcpy(&ctx->b[ctx->h.bCnt], msg, n);
		msgByteCnt  -= n;
		msg         += n;
		ctx->h.bCnt += n;
	    }

	    _skein512_process(ctx, ctx->b, 1, SKEIN_512_BLOCK_BYTES);
	    ctx->h.bCnt = 0;
	}
	if (msgByteCnt > SKEIN_512_BLOCK_BYTES){
	    n = (msgByteCnt-1) / SKEIN_512_BLOCK_BYTES;
	    _skein512_process(ctx, msg, n, SKEIN_512_BLOCK_BYTES);
	    msgByteCnt -= n * SKEIN_512_BLOCK_BYTES;
	    msg        += n * SKEIN_512_BLOCK_BYTES;
	}
    }

    if (msgByteCnt){
	memcpy(&ctx->b[ctx->h.bCnt], msg, msgByteCnt);
	ctx->h.bCnt += msgByteCnt;
    }

    return NBSCrypto_OK;
}

static inline int _skein512_final(Skein_512_Ctxt_t *ctx, unsigned char *hashVal)
{
    size_t i,n,byteCnt;
    unsigned long long X[SKEIN_512_STATE_WORDS];

    ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL;
    if (ctx->h.bCnt < SKEIN_512_BLOCK_BYTES)
	memset(&ctx->b[ctx->h.bCnt], 0, SKEIN_512_BLOCK_BYTES - ctx->h.bCnt);

    _skein512_process(ctx, ctx->b, 1, ctx->h.bCnt);

    byteCnt = (ctx->h.hashBitLen + 7) >> 3;

    memset(ctx->b, 0, sizeof(ctx->b));
    memcpy(X, ctx->X, sizeof(X));
    for (i=0;i*SKEIN_512_BLOCK_BYTES < byteCnt;i++){
	((unsigned long long *)ctx->b)[0] = _skein_swap64((unsigned long long)i);
	Skein_Start_New_Type(ctx, OUT_FINAL);
	_skein512_process(ctx, ctx->b, 1, sizeof(unsigned long long));
	n = byteCnt - i*SKEIN_512_BLOCK_BYTES;
	if (n >= SKEIN_512_BLOCK_BYTES)
	    n  = SKEIN_512_BLOCK_BYTES;

	_skein_Put64_LSB_First(hashVal+i*SKEIN_512_BLOCK_BYTES, ctx->X, n);
	memcpy(ctx->X, X, sizeof(X));
    }

    return NBSCrypto_OK;
}

static inline void _skein1024_process(Skein1024_Ctxt_t *ctx, const unsigned char *blkPtr, size_t blkCnt, size_t byteCntAdd)
{
    enum
    {
	WCNT = SKEIN1024_STATE_WORDS
    };

    size_t i,r;
    unsigned long long ts[3];
    unsigned long long ks[WCNT+1];
    unsigned long long X [WCNT];
    unsigned long long w [WCNT];

    do  {
	ctx->h.T[0] += byteCntAdd;

	ks[WCNT] = SKEIN_KS_PARITY;
	for (i=0;i < WCNT; i++)
	{
	    ks[i]     = ctx->X[i];
	    ks[WCNT] ^= ctx->X[i];
	}
	ts[0] = ctx->h.T[0];
	ts[1] = ctx->h.T[1];
	ts[2] = ts[0] ^ ts[1];

	_skein_Get64_LSB_First(w, blkPtr, WCNT);
	for (i=0;i < WCNT; i++){
	    X[i]  = w[i] + ks[i];
	}
	X[WCNT-3] += ts[0];
	X[WCNT-2] += ts[1];

	for (r=1;r <= SKEIN1024_ROUNDS_TOTAL/8; r++){
	    X[ 0] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_0_0); X[ 1] ^= X[ 0];
	    X[ 2] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_0_1); X[ 3] ^= X[ 2];
	    X[ 4] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_0_2); X[ 5] ^= X[ 4];
	    X[ 6] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_0_3); X[ 7] ^= X[ 6];
	    X[ 8] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_0_4); X[ 9] ^= X[ 8];
	    X[10] += X[11]; X[11] = _RotL_64(X[11],R1024_0_5); X[11] ^= X[10];
	    X[12] += X[13]; X[13] = _RotL_64(X[13],R1024_0_6); X[13] ^= X[12];
	    X[14] += X[15]; X[15] = _RotL_64(X[15],R1024_0_7); X[15] ^= X[14];

	    X[ 0] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_1_0); X[ 9] ^= X[ 0];
	    X[ 2] += X[13]; X[13] = _RotL_64(X[13],R1024_1_1); X[13] ^= X[ 2];
	    X[ 6] += X[11]; X[11] = _RotL_64(X[11],R1024_1_2); X[11] ^= X[ 6];
	    X[ 4] += X[15]; X[15] = _RotL_64(X[15],R1024_1_3); X[15] ^= X[ 4];
	    X[10] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_1_4); X[ 7] ^= X[10];
	    X[12] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_1_5); X[ 3] ^= X[12];
	    X[14] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_1_6); X[ 5] ^= X[14];
	    X[ 8] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_1_7); X[ 1] ^= X[ 8];

	    X[ 0] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_2_0); X[ 7] ^= X[ 0];
	    X[ 2] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_2_1); X[ 5] ^= X[ 2];
	    X[ 4] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_2_2); X[ 3] ^= X[ 4];
	    X[ 6] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_2_3); X[ 1] ^= X[ 6];
	    X[12] += X[15]; X[15] = _RotL_64(X[15],R1024_2_4); X[15] ^= X[12];
	    X[14] += X[13]; X[13] = _RotL_64(X[13],R1024_2_5); X[13] ^= X[14];
	    X[ 8] += X[11]; X[11] = _RotL_64(X[11],R1024_2_6); X[11] ^= X[ 8];
	    X[10] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_2_7); X[ 9] ^= X[10];

	    X[ 0] += X[15]; X[15] = _RotL_64(X[15],R1024_3_0); X[15] ^= X[ 0];
	    X[ 2] += X[11]; X[11] = _RotL_64(X[11],R1024_3_1); X[11] ^= X[ 2];
	    X[ 6] += X[13]; X[13] = _RotL_64(X[13],R1024_3_2); X[13] ^= X[ 6];
	    X[ 4] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_3_3); X[ 9] ^= X[ 4];
	    X[14] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_3_4); X[ 1] ^= X[14];
	    X[ 8] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_3_5); X[ 5] ^= X[ 8];
	    X[10] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_3_6); X[ 3] ^= X[10];
	    X[12] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_3_7); X[ 7] ^= X[12];
	    InjectKey(2*r-1);

	    X[ 0] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_4_0); X[ 1] ^= X[ 0];
	    X[ 2] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_4_1); X[ 3] ^= X[ 2];
	    X[ 4] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_4_2); X[ 5] ^= X[ 4];
	    X[ 6] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_4_3); X[ 7] ^= X[ 6];
	    X[ 8] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_4_4); X[ 9] ^= X[ 8];
	    X[10] += X[11]; X[11] = _RotL_64(X[11],R1024_4_5); X[11] ^= X[10];
	    X[12] += X[13]; X[13] = _RotL_64(X[13],R1024_4_6); X[13] ^= X[12];
	    X[14] += X[15]; X[15] = _RotL_64(X[15],R1024_4_7); X[15] ^= X[14];

	    X[ 0] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_5_0); X[ 9] ^= X[ 0];
	    X[ 2] += X[13]; X[13] = _RotL_64(X[13],R1024_5_1); X[13] ^= X[ 2];
	    X[ 6] += X[11]; X[11] = _RotL_64(X[11],R1024_5_2); X[11] ^= X[ 6];
	    X[ 4] += X[15]; X[15] = _RotL_64(X[15],R1024_5_3); X[15] ^= X[ 4];
	    X[10] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_5_4); X[ 7] ^= X[10];
	    X[12] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_5_5); X[ 3] ^= X[12];
	    X[14] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_5_6); X[ 5] ^= X[14];
	    X[ 8] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_5_7); X[ 1] ^= X[ 8];

	    X[ 0] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_6_0); X[ 7] ^= X[ 0];
	    X[ 2] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_6_1); X[ 5] ^= X[ 2];
	    X[ 4] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_6_2); X[ 3] ^= X[ 4];
	    X[ 6] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_6_3); X[ 1] ^= X[ 6];
	    X[12] += X[15]; X[15] = _RotL_64(X[15],R1024_6_4); X[15] ^= X[12];
	    X[14] += X[13]; X[13] = _RotL_64(X[13],R1024_6_5); X[13] ^= X[14];
	    X[ 8] += X[11]; X[11] = _RotL_64(X[11],R1024_6_6); X[11] ^= X[ 8];
	    X[10] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_6_7); X[ 9] ^= X[10];

	    X[ 0] += X[15]; X[15] = _RotL_64(X[15],R1024_7_0); X[15] ^= X[ 0];
	    X[ 2] += X[11]; X[11] = _RotL_64(X[11],R1024_7_1); X[11] ^= X[ 2];
	    X[ 6] += X[13]; X[13] = _RotL_64(X[13],R1024_7_2); X[13] ^= X[ 6];
	    X[ 4] += X[ 9]; X[ 9] = _RotL_64(X[ 9],R1024_7_3); X[ 9] ^= X[ 4];
	    X[14] += X[ 1]; X[ 1] = _RotL_64(X[ 1],R1024_7_4); X[ 1] ^= X[14];
	    X[ 8] += X[ 5]; X[ 5] = _RotL_64(X[ 5],R1024_7_5); X[ 5] ^= X[ 8];
	    X[10] += X[ 3]; X[ 3] = _RotL_64(X[ 3],R1024_7_6); X[ 3] ^= X[10];
	    X[12] += X[ 7]; X[ 7] = _RotL_64(X[ 7],R1024_7_7); X[ 7] ^= X[12];
	    InjectKey(2*r);
	}

	for (i=0;i<WCNT;i++)
	    ctx->X[i] = X[i] ^ w[i];

	Skein_Clear_First_Flag(ctx->h);
	blkPtr += SKEIN1024_BLOCK_BYTES;
    }
    while (--blkCnt);
}

static inline int _skein1024_init(Skein1024_Ctxt_t *ctx, size_t hashBitLen)
{
    union
    {
	unsigned char b[SKEIN1024_STATE_BYTES];
	unsigned long long w[SKEIN1024_STATE_WORDS];
    } cfg;

    ctx->h.hashBitLen = hashBitLen;
    Skein_Start_New_Type(ctx, CFG_FINAL);

    memset(&cfg.w, 0, sizeof(cfg.w));
    cfg.w[0] = _skein_swap64(SKEIN_SCHEMA_VER);
    cfg.w[1] = _skein_swap64(hashBitLen);
    cfg.w[2] = _skein_swap64(SKEIN_CFG_TREE_INFO_SEQUENTIAL);

    memset(ctx->X, 0, sizeof(ctx->X));
    _skein1024_process(ctx,cfg.b, 1, SKEIN_CFG_STR_LEN);

    Skein_Start_New_Type(ctx, MSG);

    return NBSCrypto_OK;
}

static inline int _skein1024_update(Skein1024_Ctxt_t *ctx, const unsigned char *msg, size_t msgByteCnt)
{
    size_t n;

    if (msgByteCnt + ctx->h.bCnt > SKEIN1024_BLOCK_BYTES){
	if (ctx->h.bCnt){
	    n = SKEIN1024_BLOCK_BYTES - ctx->h.bCnt;
	    if (n){
		memcpy(&ctx->b[ctx->h.bCnt], msg, n);
		msgByteCnt  -= n;
		msg         += n;
		ctx->h.bCnt += n;
	    }
	    _skein1024_process(ctx, ctx->b, 1, SKEIN1024_BLOCK_BYTES);
	    ctx->h.bCnt = 0;
	}
	if (msgByteCnt > SKEIN1024_BLOCK_BYTES){
	    n = (msgByteCnt-1) / SKEIN1024_BLOCK_BYTES;
	    _skein1024_process(ctx, msg, n, SKEIN1024_BLOCK_BYTES);
	    msgByteCnt -= n * SKEIN1024_BLOCK_BYTES;
	    msg        += n * SKEIN1024_BLOCK_BYTES;
	}
    }

    if (msgByteCnt){
	memcpy(&ctx->b[ctx->h.bCnt],msg,msgByteCnt);
	ctx->h.bCnt += msgByteCnt;
    }

    return NBSCrypto_OK;
}

static inline int _skein1024_final(Skein1024_Ctxt_t *ctx, unsigned char *hashVal)
{
    size_t i,n,byteCnt;
    unsigned long long X[SKEIN1024_STATE_WORDS];

    ctx->h.T[1] |= SKEIN_T1_FLAG_FINAL;
    if (ctx->h.bCnt < SKEIN1024_BLOCK_BYTES)
	memset(&ctx->b[ctx->h.bCnt], 0, SKEIN1024_BLOCK_BYTES - ctx->h.bCnt);

    _skein1024_process(ctx, ctx->b, 1, ctx->h.bCnt);

    byteCnt = (ctx->h.hashBitLen + 7) >> 3;

    memset(ctx->b, 0, sizeof(ctx->b));
    memcpy(X, ctx->X, sizeof(X));
    for (i=0;i*SKEIN1024_BLOCK_BYTES < byteCnt;i++){
	((unsigned long long *)ctx->b)[0]= _skein_swap64((unsigned long long) i);
	Skein_Start_New_Type(ctx, OUT_FINAL);
	_skein1024_process(ctx, ctx->b, 1, sizeof(unsigned long long));
	n = byteCnt - i*SKEIN1024_BLOCK_BYTES;
	if (n >= SKEIN1024_BLOCK_BYTES)
	    n  = SKEIN1024_BLOCK_BYTES;

	_skein_Put64_LSB_First(hashVal+i*SKEIN1024_BLOCK_BYTES,ctx->X,n);
	memcpy(ctx->X, X, sizeof(X));
    }

    return NBSCrypto_OK;
}

static inline int _skein_init(hash_state *hs, int hashbits, int hashbitlen)
{
    switch (hashbits) {
	case 256:{
	    if (hashbitlen <= SKEIN_256_NIST_MAX_HASHBITS){
		hs->skein.statebits = 64*SKEIN_256_STATE_WORDS;
		return _skein256_init(&hs->skein.u.ctx_256, (size_t)hashbitlen);
	    }
	    break;
	}
	case 512:{
	    if (hashbitlen <= SKEIN_512_NIST_MAX_HASHBITS){
		hs->skein.statebits = 64*SKEIN_512_STATE_WORDS;
		return _skein512_init(&hs->skein.u.ctx_512, (size_t)hashbitlen);
	    }
	    break;
	}
	default:{
	    hs->skein.statebits = 64*SKEIN1024_STATE_WORDS;
	    return _skein1024_init(&hs->skein.u.ctx1024, (size_t)hashbitlen);
	    break;
	}
    }

    return NBSCrypto_ERROR;
}




#pragma mark - FUNCTIONS

int skein_224_init(hash_state *hs){ return _skein_init(hs, 512,  224);}
int skein_256_init(hash_state *hs){ return _skein_init(hs, 512,  256);}
int skein_384_init(hash_state *hs){ return _skein_init(hs, 512,  384);}
int skein_512_init(hash_state *hs){ return _skein_init(hs, 512,  512);}
int skein_1024_init(hash_state *hs){return _skein_init(hs,   0, 1024);}

int skein_process(hash_state *hs, const unsigned char *in, unsigned long inlen)
{
    if ((inlen & 7) == 0){
	switch ((hs->skein.statebits >> 8) & 3){
	    case 2:  return  _skein512_update(&hs->skein.u.ctx_512, in, inlen >> 3);
	    case 1:  return  _skein256_update(&hs->skein.u.ctx_256, in, inlen >> 3);
	    case 0:  return _skein1024_update(&hs->skein.u.ctx1024, in, inlen >> 3);
	    default: return NBSCrypto_ERROR;
	}
    }else{
	size_t bCnt = (inlen >> 3) + 1;
	unsigned char b,mask;

	mask = (unsigned char) (1u << (7 - (inlen & 7)));
	b    = (unsigned char) ((in[bCnt-1] & (0-mask)) | mask);

	switch ((hs->skein.statebits >> 8) & 3){
	    case 2:{
		_skein512_update(&hs->skein.u.ctx_512, in,bCnt-1);
		_skein512_update(&hs->skein.u.ctx_512, &b, 1);
		break;
	    }
	    case 1:{
		_skein256_update(&hs->skein.u.ctx_256, in,bCnt-1);
		_skein256_update(&hs->skein.u.ctx_256, &b,1);
		break;
	    }
	    case 0:{
		_skein1024_update(&hs->skein.u.ctx1024, in,bCnt-1);
		_skein1024_update(&hs->skein.u.ctx1024, &b, 1);
		break;
	    }
	    default: return NBSCrypto_ERROR;
	}
	Skein_Set_Bit_Pad_Flag(hs->skein.u.h);

	return NBSCrypto_OK;
    }
}

int skein_done(hash_state *hs, unsigned char *out)
{
    switch ((hs->skein.statebits >> 8) & 3){
	case 2:  return  _skein512_final(&hs->skein.u.ctx_512, out);
	case 1:  return  _skein256_final(&hs->skein.u.ctx_256, out);
	case 0:  return _skein1024_final(&hs->skein.u.ctx1024, out);
	default: return NBSCrypto_ERROR;
    }
}

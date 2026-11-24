//
//	argon2.c
//	Authors / Developers		: Daniel Dinu, Dmitry Khovratovich, Jean-Philippe Aumasson, Samuel Neves
//	Last Modified (Original)	: 2015
//

#include "nbs_crypto.h"
#include <limits.h>
#include <pthread.h>



#define ARGON2_MIN_LANES UINT32_C(1)
#define ARGON2_MAX_LANES UINT32_C(0xFFFFFF)
#define ARGON2_MIN_THREADS UINT32_C(1)
#define ARGON2_MAX_THREADS UINT32_C(0xFFFFFF)
#define ARGON2_SYNC_POINTS UINT32_C(4)
#define ARGON2_MIN_OUTLEN UINT32_C(4)
#define ARGON2_MAX_OUTLEN UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_MEMORY (2 * ARGON2_SYNC_POINTS)
#define ARGON2_MIN(a, b) ((a) < (b) ? (a) : (b))
#define ARGON2_MAX_MEMORY_BITS	ARGON2_MIN(UINT32_C(32), (sizeof(void *) * CHAR_BIT - 10 - 1))
#define ARGON2_MAX_MEMORY	ARGON2_MIN(UINT32_C(0xFFFFFFFF), UINT64_C(1) << ARGON2_MAX_MEMORY_BITS)
#define ARGON2_MIN_TIME UINT32_C(1)
#define ARGON2_MAX_TIME UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_PWD_LENGTH UINT32_C(0)
#define ARGON2_MAX_PWD_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_AD_LENGTH UINT32_C(0)
#define ARGON2_MAX_AD_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_SALT_LENGTH UINT32_C(8)
#define ARGON2_MAX_SALT_LENGTH UINT32_C(0xFFFFFFFF)
#define ARGON2_MIN_SECRET UINT32_C(0)
#define ARGON2_MAX_SECRET UINT32_C(0xFFFFFFFF)
#define ARGON2_DEFAULT_FLAGS UINT32_C(0)
#define ARGON2_FLAG_CLEAR_PASSWORD (UINT32_C(1) << 0)
#define ARGON2_FLAG_CLEAR_SECRET (UINT32_C(1) << 1)

#define ARGON2_MAX_DECODED_LANES UINT32_C(255)
#define ARGON2_MIN_DECODED_SALT_LEN UINT32_C(8)
#define ARGON2_MIN_DECODED_OUT_LEN UINT32_C(12)
#define EQ(x, y) ((((0U - ((unsigned)(x) ^ (unsigned)(y))) >> 8) & 0xFF) ^ 0xFF)
#define GT(x, y) ((((unsigned)(y) - (unsigned)(x)) >> 8) & 0xFF)
#define GE(x, y) (GT(y, x) ^ 0xFF)
#define LT(x, y) GT(y, x)
#define LE(x, y) GE(y, x)

#define CONST_CAST(x) (x)(uintptr_t)

//Blake2b
#define G(a, b, c, d)		\
do {				\
    a = fBlaMka(a, b);		\
    d = rotr64(d ^ a, 32);	\
    c = fBlaMka(c, d);		\
    b = rotr64(b ^ c, 24);	\
    a = fBlaMka(a, b);		\
    d = rotr64(d ^ a, 16);	\
    c = fBlaMka(c, d);		\
    b = rotr64(b ^ c, 63);	\
} while ((void)0, 0)

//Blake2b
#define ARGON2_BLAKE2_ROUND_NOMSG(v0, v1, v2, v3, v4, v5, v6, v7, v8, v9, v10, v11, v12, v13, v14, v15)	\
do {													\
    G(v0, v4,  v8, v12);										\
    G(v1, v5,  v9, v13);										\
    G(v2, v6, v10, v14);										\
    G(v3, v7, v11, v15);										\
    G(v0, v5, v10, v15);										\
    G(v1, v6, v11, v12);										\
    G(v2, v7,  v8, v13);										\
    G(v3, v4,  v9, v14);										\
} while ((void)0, 0)

enum argon2_core_constants {
    ARGON2_BLOCK_SIZE = 1024,
    ARGON2_QWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 8,
    ARGON2_OWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 16,
    ARGON2_HWORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 32,
    ARGON2_512BIT_WORDS_IN_BLOCK = ARGON2_BLOCK_SIZE / 64,
    ARGON2_ADDRESSES_IN_BLOCK = 128,
    ARGON2_PREHASH_DIGEST_LENGTH = 64,
    ARGON2_PREHASH_SEED_LENGTH = 72
};

//Blake2b
enum argon2_blake2b_constant {
    BLAKE2B_BLOCKBYTES = 128,
    BLAKE2B_OUTBYTES = 64,
    BLAKE2B_KEYBYTES = 64,
    BLAKE2B_SALTBYTES = 16,
    BLAKE2B_PERSONALBYTES = 16
};

//Blake2b
typedef struct __argon2_blake2b_state {
    uint64_t h[8];
    uint64_t t[2];
    uint64_t f[2];
    uint8_t buf[BLAKE2B_BLOCKBYTES];
    unsigned buflen;
    unsigned outlen;
    uint8_t last_node;
} argon2_blake2b_state;

typedef struct __argon2_blake2b_param {
    uint8_t digest_length;                   /* 1 */
    uint8_t key_length;                      /* 2 */
    uint8_t fanout;                          /* 3 */
    uint8_t depth;                           /* 4 */
    uint32_t leaf_length;                    /* 8 */
    uint64_t node_offset;                    /* 16 */
    uint8_t node_depth;                      /* 17 */
    uint8_t inner_length;                    /* 18 */
    uint8_t reserved[14];                    /* 32 */
    uint8_t salt[BLAKE2B_SALTBYTES];         /* 48 */
    uint8_t personal[BLAKE2B_PERSONALBYTES]; /* 64 */
} argon2_blake2b_param;


extern int FLAG_clear_internal_memory;

typedef int (*allocate_fptr)(uint8_t **memory, size_t bytes_to_allocate);
typedef void (*deallocate_fptr)(uint8_t *memory, size_t bytes_to_allocate);

typedef void *(*argon2_thread_func_t)(void *);
typedef pthread_t argon2_thread_handle_t;

typedef struct block_ { uint64_t v[ARGON2_QWORDS_IN_BLOCK]; } block;

typedef struct Argon2_Context {
    uint8_t *out;
    uint32_t outlen;
    uint8_t *pwd;
    uint32_t pwdlen;
    uint8_t *salt;
    uint32_t saltlen;
    uint8_t *secret;
    uint32_t secretlen;
    uint8_t *ad;
    uint32_t adlen;
    uint32_t t_cost;
    uint32_t m_cost;
    uint32_t lanes;
    uint32_t threads;
    uint32_t version;
    allocate_fptr allocate_cbk;
    deallocate_fptr free_cbk;
    uint32_t flags;
} argon2_context;

typedef struct Argon2_instance_t {
    block *memory;
    uint32_t version;
    uint32_t passes;
    uint32_t memory_blocks;
    uint32_t segment_length;
    uint32_t lane_length;
    uint32_t lanes;
    uint32_t threads;
    argon2_type type;
    int print_internals;
    argon2_context *context_ptr;
} argon2_instance_t;

typedef struct Argon2_position_t {
    uint32_t pass;
    uint32_t lane;
    uint8_t slice;
    uint32_t index;
} argon2_position_t;

typedef struct Argon2_thread_data {
    argon2_instance_t *instance_ptr;
    argon2_position_t pos;
} argon2_thread_data;

const char *argon2_type2string(argon2_type type, int uppercase) {
    switch (type) {
	case Argon2_d:
	    return uppercase ? "Argon2d" : "argon2d";
	case Argon2_i:
	    return uppercase ? "Argon2i" : "argon2i";
	case Argon2_id:
	    return uppercase ? "Argon2id" : "argon2id";
    }
    return NULL;
}




//Blake2b
static inline uint64_t fBlaMka(uint64_t x, uint64_t y)
{
    const uint64_t m = UINT64_C(0xFFFFFFFF);
    const uint64_t xy = (x & m) * (y & m);
    return x + y + 2 * xy;
}

/*
static inline uint32_t load32(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    uint32_t w = *p++;
    w |= (uint32_t)(*p++) << 8;
    w |= (uint32_t)(*p++) << 16;
    w |= (uint32_t)(*p++) << 24;
    return w;
}
 */

static inline void store32(void *dst, uint32_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

static inline uint64_t load64(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    w |= (uint64_t)(*p++) << 48;
    w |= (uint64_t)(*p++) << 56;
    return w;
}

static inline void store64(void *dst, uint64_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}

/*
static inline uint64_t load48(const void *src)
{
    const uint8_t *p = (const uint8_t *)src;
    uint64_t w = *p++;
    w |= (uint64_t)(*p++) << 8;
    w |= (uint64_t)(*p++) << 16;
    w |= (uint64_t)(*p++) << 24;
    w |= (uint64_t)(*p++) << 32;
    w |= (uint64_t)(*p++) << 40;
    return w;
}
 */

/*
static inline void store48(void *dst, uint64_t w)
{
    uint8_t *p = (uint8_t *)dst;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
    w >>= 8;
    *p++ = (uint8_t)w;
}
 */

/*
static inline uint32_t rotr32(const uint32_t w, const unsigned c)
{
    return (w >> c) | (w << (32 - c));
}
*/

static inline uint64_t rotr64(const uint64_t w, const unsigned c)
{
    return (w >> c) | (w << (64 - c));
}




//ARGON2 THREADS
static inline int argon2_thread_create(argon2_thread_handle_t *handle, argon2_thread_func_t func, void *args)
{
    if (NULL == handle || func == NULL) {
	return -1;
    }
    return pthread_create(handle, NULL, func, args);
}

static inline int argon2_thread_join(argon2_thread_handle_t handle)
{
    return pthread_join(handle, NULL);
}

static inline void argon2_thread_exit(void)
{
    pthread_exit(NULL);
}





/***************Instance and Position constructors**********/
static inline void init_block_value(block *b, uint8_t in)
{
    memset(b->v, in, sizeof(b->v));
}

static inline void copy_block(block *dst, const block *src)
{
    memcpy(dst->v, src->v, sizeof(uint64_t) * ARGON2_QWORDS_IN_BLOCK);
}

static inline void xor_block(block *dst, const block *src)
{
    int i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
	dst->v[i] ^= src->v[i];
    }
}

static inline void load_block(block *dst, const void *input)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
	dst->v[i] = load64((const uint8_t *)input + i * sizeof(dst->v[i]));
    }
}

static inline void store_block(void *output, const block *src)
{
    unsigned i;
    for (i = 0; i < ARGON2_QWORDS_IN_BLOCK; ++i) {
	store64((uint8_t *)output + i * sizeof(src->v[i]), src->v[i]);
    }
}

static inline void fill_block(const block *prev_block, const block *ref_block, block *next_block, int with_xor)
{
    block blockR, block_tmp;
    unsigned i;

    copy_block(&blockR, ref_block);
    xor_block(&blockR, prev_block);
    copy_block(&block_tmp, &blockR);

    if (with_xor) {
	xor_block(&block_tmp, next_block);
    }

    for (i = 0; i < 8; ++i) {
	ARGON2_BLAKE2_ROUND_NOMSG(
			   blockR.v[16 * i], blockR.v[16 * i + 1], blockR.v[16 * i + 2],
			   blockR.v[16 * i + 3], blockR.v[16 * i + 4], blockR.v[16 * i + 5],
			   blockR.v[16 * i + 6], blockR.v[16 * i + 7], blockR.v[16 * i + 8],
			   blockR.v[16 * i + 9], blockR.v[16 * i + 10], blockR.v[16 * i + 11],
			   blockR.v[16 * i + 12], blockR.v[16 * i + 13], blockR.v[16 * i + 14],
			   blockR.v[16 * i + 15]);
    }

    for (i = 0; i < 8; i++) {
	ARGON2_BLAKE2_ROUND_NOMSG(
			   blockR.v[2 * i], blockR.v[2 * i + 1], blockR.v[2 * i + 16],
			   blockR.v[2 * i + 17], blockR.v[2 * i + 32], blockR.v[2 * i + 33],
			   blockR.v[2 * i + 48], blockR.v[2 * i + 49], blockR.v[2 * i + 64],
			   blockR.v[2 * i + 65], blockR.v[2 * i + 80], blockR.v[2 * i + 81],
			   blockR.v[2 * i + 96], blockR.v[2 * i + 97], blockR.v[2 * i + 112],
			   blockR.v[2 * i + 113]);
    }

    copy_block(next_block, &block_tmp);
    xor_block(next_block, &blockR);
}

static inline uint32_t index_alpha(const argon2_instance_t *instance, const argon2_position_t *position, uint32_t pseudo_rand, int same_lane)
{
    uint32_t reference_area_size;
    uint64_t relative_position;
    uint32_t start_position, absolute_position;

    if (0 == position->pass) {
	if (0 == position->slice) {
	    reference_area_size = position->index - 1;
	} else {
	    if (same_lane) {
		reference_area_size = position->slice * instance->segment_length + position->index - 1;
	    } else {
		reference_area_size = position->slice * instance->segment_length + ((position->index == 0) ? (-1) : 0);
	    }
	}
    } else {
	if (same_lane) {
	    reference_area_size = instance->lane_length - instance->segment_length + position->index - 1;
	} else {
	    reference_area_size = instance->lane_length - instance->segment_length + ((position->index == 0) ? (-1) : 0);
	}
    }

    relative_position = pseudo_rand;
    relative_position = relative_position * relative_position >> 32;
    relative_position = reference_area_size - 1 - (reference_area_size * relative_position >> 32);

    start_position = 0;

    if (0 != position->pass) {
	start_position = (position->slice == ARGON2_SYNC_POINTS - 1) ? 0 : (position->slice + 1) * instance->segment_length;
    }

    absolute_position = (start_position + relative_position) % instance->lane_length;
    return absolute_position;
}

static inline void next_addresses(block *address_block, block *input_block, const block *zero_block)
{
    input_block->v[6]++;
    fill_block(zero_block, input_block, address_block, 0);
    fill_block(zero_block, address_block, address_block, 0);
}

static inline void fill_segment(const argon2_instance_t *instance, argon2_position_t position)
{
    block *ref_block = NULL, *curr_block = NULL;
    block address_block, input_block, zero_block;
    uint64_t pseudo_rand, ref_index, ref_lane;
    uint32_t prev_offset, curr_offset;
    uint32_t starting_index;
    uint32_t i;
    int data_independent_addressing;

    if (instance == NULL) {
	return;
    }

    data_independent_addressing =
    (instance->type == Argon2_i) ||
    (instance->type == Argon2_id && (position.pass == 0) &&
     (position.slice < ARGON2_SYNC_POINTS / 2));

    if (data_independent_addressing) {
	init_block_value(&zero_block, 0);
	init_block_value(&input_block, 0);

	input_block.v[0] = position.pass;
	input_block.v[1] = position.lane;
	input_block.v[2] = position.slice;
	input_block.v[3] = instance->memory_blocks;
	input_block.v[4] = instance->passes;
	input_block.v[5] = instance->type;
    }

    starting_index = 0;

    if ((0 == position.pass) && (0 == position.slice)) {
	starting_index = 2; /* we have already generated the first two blocks */

	/* Don't forget to generate the first block of addresses: */
	if (data_independent_addressing) {
	    next_addresses(&address_block, &input_block, &zero_block);
	}
    }

    /* Offset of the current block */
    curr_offset = position.lane * instance->lane_length +
    position.slice * instance->segment_length + starting_index;

    if (0 == curr_offset % instance->lane_length) {
	/* Last block in this lane */
	prev_offset = curr_offset + instance->lane_length - 1;
    } else {
	/* Previous block */
	prev_offset = curr_offset - 1;
    }

    for (i = starting_index; i < instance->segment_length;
	 ++i, ++curr_offset, ++prev_offset) {
	/*1.1 Rotating prev_offset if needed */
	if (curr_offset % instance->lane_length == 1) {
	    prev_offset = curr_offset - 1;
	}

	/* 1.2 Computing the index of the reference block */
	/* 1.2.1 Taking pseudo-random value from the previous block */
	if (data_independent_addressing) {
	    if (i % ARGON2_ADDRESSES_IN_BLOCK == 0) {
		next_addresses(&address_block, &input_block, &zero_block);
	    }
	    pseudo_rand = address_block.v[i % ARGON2_ADDRESSES_IN_BLOCK];
	} else {
	    pseudo_rand = instance->memory[prev_offset].v[0];
	}

	/* 1.2.2 Computing the lane of the reference block */
	ref_lane = ((pseudo_rand >> 32)) % instance->lanes;

	if ((position.pass == 0) && (position.slice == 0)) {
	    /* Can not reference other lanes yet */
	    ref_lane = position.lane;
	}

	/* 1.2.3 Computing the number of possible reference block within the
	 * lane.
	 */
	position.index = i;
	ref_index = index_alpha(instance, &position, pseudo_rand & 0xFFFFFFFF, ref_lane == position.lane);

	/* 2 Creating a new block */
	ref_block =
	instance->memory + instance->lane_length * ref_lane + ref_index;
	curr_block = instance->memory + curr_offset;
	if (ARGON2_VERSION_10 == instance->version) {
	    /* version 1.2.1 and earlier: overwrite, not XOR */
	    fill_block(instance->memory + prev_offset, ref_block, curr_block, 0);
	} else {
	    if(0 == position.pass) {
		fill_block(instance->memory + prev_offset, ref_block,
			   curr_block, 0);
	    } else {
		fill_block(instance->memory + prev_offset, ref_block,
			   curr_block, 1);
	    }
	}
    }
}

/***************Memory functions*****************/
static inline int allocate_memory(const argon2_context *context, uint8_t **memory, size_t num, size_t size)
{
    size_t memory_size = num*size;
    if (memory == NULL) {
	return NBSCrypto_ERROR;
    }

    /* 1. Check for multiplication overflow */
    if (size != 0 && memory_size / size != num) {
	return NBSCrypto_ERROR;
    }

    /* 2. Try to allocate with appropriate allocator */
    if (context->allocate_cbk) {
	(context->allocate_cbk)(memory, memory_size);
    } else {
	*memory = malloc(memory_size);
    }

    if (*memory == NULL) {
	return NBSCrypto_ERROR;
    }

    return NBSCrypto_OK;
}

static inline void secure_wipe_memory(void *v, size_t n)
{
    static void *(*const volatile memset_sec)(void *, int, size_t) = &memset;
    memset_sec(v, 0, n);
}

int FLAG_clear_internal_memory = 1;

static inline void clear_internal_memory(void *v, size_t n)
{
    if (FLAG_clear_internal_memory && v) {
	secure_wipe_memory(v, n);
    }
}

static inline void free_memory(const argon2_context *context, uint8_t *memory, size_t num, size_t size)
{
    size_t memory_size = num*size;
    clear_internal_memory(memory, memory_size);
    if (context->free_cbk) {
	(context->free_cbk)(memory, memory_size);
    } else {
	free(memory);
    }
}

static inline void *fill_segment_thr(void *thread_data)
{
    argon2_thread_data *my_data = thread_data;
    fill_segment(my_data->instance_ptr, my_data->pos);
    argon2_thread_exit();
    return 0;
}

static inline int fill_memory_blocks_st(argon2_instance_t *instance)
{
    uint32_t r, s, l;

    for (r = 0; r < instance->passes; ++r) {
	for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
	    for (l = 0; l < instance->lanes; ++l) {
		argon2_position_t position = {r, l, (uint8_t)s, 0};
		fill_segment(instance, position);
	    }
	}
    }
    return NBSCrypto_OK;
}

static inline int fill_memory_blocks_mt(argon2_instance_t *instance)
{
    uint32_t r, s;
    argon2_thread_handle_t *thread = NULL;
    argon2_thread_data *thr_data = NULL;
    int rc = NBSCrypto_OK;

    thread = calloc(instance->lanes, sizeof(argon2_thread_handle_t));
    if (thread == NULL) {
	rc = NBSCrypto_ERROR;
	goto fail;
    }

    thr_data = calloc(instance->lanes, sizeof(argon2_thread_data));
    if (thr_data == NULL) {
	rc = NBSCrypto_ERROR;
	goto fail;
    }

    for (r = 0; r < instance->passes; ++r) {
	for (s = 0; s < ARGON2_SYNC_POINTS; ++s) {
	    uint32_t l, ll;

	    for (l = 0; l < instance->lanes; ++l) {
		argon2_position_t position;

		if (l >= instance->threads) {
		    if (argon2_thread_join(thread[l - instance->threads])) {
			rc = NBSCrypto_ERROR;
			goto fail;
		    }
		}

		position.pass = r;
		position.lane = l;
		position.slice = (uint8_t)s;
		position.index = 0;
		thr_data[l].instance_ptr =
		instance;
		memcpy(&(thr_data[l].pos), &position,
		       sizeof(argon2_position_t));
		if (argon2_thread_create(&thread[l], &fill_segment_thr,(void *)&thr_data[l])) {
		    for (ll = 0; ll < l; ++ll)
			argon2_thread_join(thread[ll]);
		    rc = NBSCrypto_ERROR;
		    goto fail;
		}
	    }

	    for (l = instance->lanes - instance->threads; l < instance->lanes;
		 ++l) {
		if (argon2_thread_join(thread[l])) {
		    rc = NBSCrypto_ERROR;
		    goto fail;
		}
	    }
	}
    }

fail:
    if (thread != NULL) {
	free(thread);
    }
    if (thr_data != NULL) {
	free(thr_data);
    }
    return rc;
}

static inline int fill_memory_blocks(argon2_instance_t *instance)
{
    if (instance == NULL || instance->lanes == 0) {
	return NBSCrypto_ERROR;
    }
#if defined(ARGON2_NO_THREADS)
    return fill_memory_blocks_st(instance);
#else
    return instance->threads == 1 ?
    fill_memory_blocks_st(instance) : fill_memory_blocks_mt(instance);
#endif
}

static inline int validate_inputs(const argon2_context *context)
{
    if (NULL == context) {
	return NBSCrypto_ERROR;
    }

    if (NULL == context->out) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MIN_OUTLEN > context->outlen) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_OUTLEN < context->outlen) {
	return NBSCrypto_ERROR;
    }

    if (NULL == context->pwd) {
	if (0 != context->pwdlen) {
	    return NBSCrypto_ERROR;
	}
    }

    if (ARGON2_MIN_PWD_LENGTH > context->pwdlen) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_PWD_LENGTH < context->pwdlen) {
	return NBSCrypto_ERROR;
    }

    if (NULL == context->salt) {
	if (0 != context->saltlen) {
	    return NBSCrypto_ERROR;
	}
    }

    if (ARGON2_MIN_SALT_LENGTH > context->saltlen) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_SALT_LENGTH < context->saltlen) {
	return NBSCrypto_ERROR;
    }

    if (NULL == context->secret) {
	if (0 != context->secretlen) {
	    return NBSCrypto_ERROR;
	}
    } else {
	if (ARGON2_MIN_SECRET > context->secretlen) {
	    return NBSCrypto_ERROR;
	}
	if (ARGON2_MAX_SECRET < context->secretlen) {
	    return NBSCrypto_ERROR;
	}
    }

    if (NULL == context->ad) {
	if (0 != context->adlen) {
	    return NBSCrypto_ERROR;
	}
    } else {
	if (ARGON2_MIN_AD_LENGTH > context->adlen) {
	    return NBSCrypto_ERROR;
	}
	if (ARGON2_MAX_AD_LENGTH < context->adlen) {
	    return NBSCrypto_ERROR;
	}
    }

    if (ARGON2_MIN_MEMORY > context->m_cost) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_MEMORY < context->m_cost) {
	return NBSCrypto_ERROR;
    }

    if (context->m_cost < 8 * context->lanes) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MIN_TIME > context->t_cost) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_TIME < context->t_cost) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MIN_LANES > context->lanes) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_LANES < context->lanes) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MIN_THREADS > context->threads) {
	return NBSCrypto_ERROR;
    }

    if (ARGON2_MAX_THREADS < context->threads) {
	return NBSCrypto_ERROR;
    }

    if (NULL != context->allocate_cbk && NULL == context->free_cbk) {
	return NBSCrypto_ERROR;
    }

    if (NULL == context->allocate_cbk && NULL != context->free_cbk) {
	return NBSCrypto_ERROR;
    }

    return NBSCrypto_OK;
}




//Blake2b
static const uint64_t blake2b_IV[8] = {
    UINT64_C(0x6a09e667f3bcc908), UINT64_C(0xbb67ae8584caa73b),
    UINT64_C(0x3c6ef372fe94f82b), UINT64_C(0xa54ff53a5f1d36f1),
    UINT64_C(0x510e527fade682d1), UINT64_C(0x9b05688c2b3e6c1f),
    UINT64_C(0x1f83d9abfb41bd6b), UINT64_C(0x5be0cd19137e2179)};

static const unsigned int blake2b_sigma[12][16] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
    {11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
    {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
    {9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
    {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
    {12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
    {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
    {6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
    {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
    {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
};

static inline void argon2_blake2b_set_lastnode(argon2_blake2b_state *S) {
    S->f[1] = (uint64_t)-1;
}

static inline void argon2_blake2b_set_lastblock(argon2_blake2b_state *S) {
    if (S->last_node) {
	argon2_blake2b_set_lastnode(S);
    }
    S->f[0] = (uint64_t)-1;
}

static inline void argon2_blake2b_increment_counter(argon2_blake2b_state *S, uint64_t inc)
{
    S->t[0] += inc;
    S->t[1] += (S->t[0] < inc);
}

static inline void blake2b_invalidate_state(argon2_blake2b_state *S)
{
    clear_internal_memory(S, sizeof(*S));
    argon2_blake2b_set_lastblock(S);
}

static inline void argon2_blake2b_init0(argon2_blake2b_state *S)
{
    memset(S, 0, sizeof(*S));
    memcpy(S->h, blake2b_IV, sizeof(S->h));
}

static inline int argon2_blake2b_init_param(argon2_blake2b_state *S, const argon2_blake2b_param *P)
{
    const unsigned char *p = (const unsigned char *)P;
    unsigned int i;

    if (NULL == P || NULL == S) {
	return -1;
    }

    argon2_blake2b_init0(S);
    for (i = 0; i < 8; ++i) {
	S->h[i] ^= load64(&p[i * sizeof(S->h[i])]);
    }
    S->outlen = P->digest_length;
    return 0;
}

static inline void argon2_blake2b_compress(argon2_blake2b_state *S, const uint8_t *block)
{
    uint64_t m[16];
    uint64_t v[16];
    unsigned int i, r;

    for (i = 0; i < 16; ++i) {
	m[i] = load64(block + i * sizeof(m[i]));
    }

    for (i = 0; i < 8; ++i) {
	v[i] = S->h[i];
    }

    v[ 8] = blake2b_IV[0];
    v[ 9] = blake2b_IV[1];
    v[10] = blake2b_IV[2];
    v[11] = blake2b_IV[3];
    v[12] = blake2b_IV[4] ^ S->t[0];
    v[13] = blake2b_IV[5] ^ S->t[1];
    v[14] = blake2b_IV[6] ^ S->f[0];
    v[15] = blake2b_IV[7] ^ S->f[1];

#define iG(r, i, a, b, c, d)			\
do {						\
    a = a + b + m[blake2b_sigma[r][2 * i + 0]];	\
    d = rotr64(d ^ a, 32);			\
    c = c + d;					\
    b = rotr64(b ^ c, 24);			\
    a = a + b + m[blake2b_sigma[r][2 * i + 1]];	\
    d = rotr64(d ^ a, 16);			\
    c = c + d;					\
    b = rotr64(b ^ c, 63);			\
} while ((void)0, 0)

#define ROUND(r)			\
do {					\
    iG(r, 0, v[0], v[4], v[ 8], v[12]);	\
    iG(r, 1, v[1], v[5], v[ 9], v[13]);	\
    iG(r, 2, v[2], v[6], v[10], v[14]);	\
    iG(r, 3, v[3], v[7], v[11], v[15]);	\
    iG(r, 4, v[0], v[5], v[10], v[15]);	\
    iG(r, 5, v[1], v[6], v[11], v[12]);	\
    iG(r, 6, v[2], v[7], v[ 8], v[13]);	\
    iG(r, 7, v[3], v[4], v[ 9], v[14]);	\
} while ((void)0, 0)

    for (r = 0; r < 12; ++r) {
	ROUND(r);
    }

    for (i = 0; i < 8; ++i) {
	S->h[i] = S->h[i] ^ v[i] ^ v[i + 8];
    }

#undef iG
#undef ROUND
}

static inline int argon2_blake2b_update(argon2_blake2b_state *S, const void *in, size_t inlen)
{
    const uint8_t *pin = (const uint8_t *)in;

    if (inlen == 0) {
	return 0;
    }

    if (S == NULL || in == NULL) {
	return -1;
    }
    if (S->f[0] != 0) {
	return -1;
    }

    if (S->buflen + inlen > BLAKE2B_BLOCKBYTES) {
	size_t left = S->buflen;
	size_t fill = BLAKE2B_BLOCKBYTES - left;
	memcpy(&S->buf[left], pin, fill);
	argon2_blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
	argon2_blake2b_compress(S, S->buf);
	S->buflen = 0;
	inlen -= fill;
	pin += fill;
	while (inlen > BLAKE2B_BLOCKBYTES) {
	    argon2_blake2b_increment_counter(S, BLAKE2B_BLOCKBYTES);
	    argon2_blake2b_compress(S, pin);
	    inlen -= BLAKE2B_BLOCKBYTES;
	    pin += BLAKE2B_BLOCKBYTES;
	}
    }
    memcpy(&S->buf[S->buflen], pin, inlen);
    S->buflen += (unsigned int)inlen;
    return 0;
}

static inline int argon2_blake2b_init(argon2_blake2b_state *S, size_t outlen)
{
    argon2_blake2b_param P;

    if (S == NULL) {
	return -1;
    }

    if ((outlen == 0) || (outlen > BLAKE2B_OUTBYTES)) {
	blake2b_invalidate_state(S);
	return -1;
    }

    P.digest_length = (uint8_t)outlen;
    P.key_length = 0;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    return argon2_blake2b_init_param(S, &P);
}

static inline int argon2_blake2b_init_key(argon2_blake2b_state *S, size_t outlen, const void *key, size_t keylen)
{
    argon2_blake2b_param P;

    if (S == NULL) {
	return -1;
    }

    if ((outlen == 0) || (outlen > BLAKE2B_OUTBYTES)) {
	blake2b_invalidate_state(S);
	return -1;
    }

    if ((key == 0) || (keylen == 0) || (keylen > BLAKE2B_KEYBYTES)) {
	blake2b_invalidate_state(S);
	return -1;
    }

    P.digest_length = (uint8_t)outlen;
    P.key_length = (uint8_t)keylen;
    P.fanout = 1;
    P.depth = 1;
    P.leaf_length = 0;
    P.node_offset = 0;
    P.node_depth = 0;
    P.inner_length = 0;
    memset(P.reserved, 0, sizeof(P.reserved));
    memset(P.salt, 0, sizeof(P.salt));
    memset(P.personal, 0, sizeof(P.personal));

    if (argon2_blake2b_init_param(S, &P) < 0) {
	blake2b_invalidate_state(S);
	return -1;
    }

    {
	uint8_t block[BLAKE2B_BLOCKBYTES];
	memset(block, 0, BLAKE2B_BLOCKBYTES);
	memcpy(block, key, keylen);
	argon2_blake2b_update(S, block, BLAKE2B_BLOCKBYTES);
	clear_internal_memory(block, BLAKE2B_BLOCKBYTES);
    }
    return 0;
}

static inline int argon2_blake2b_final(argon2_blake2b_state *S, void *out, size_t outlen)
{
    uint8_t buffer[BLAKE2B_OUTBYTES] = {0};
    unsigned int i;

    if (S == NULL || out == NULL || outlen < S->outlen) {
	return -1;
    }

    if (S->f[0] != 0) {
	return -1;
    }

    argon2_blake2b_increment_counter(S, S->buflen);
    argon2_blake2b_set_lastblock(S);
    memset(&S->buf[S->buflen], 0, BLAKE2B_BLOCKBYTES - S->buflen);
    argon2_blake2b_compress(S, S->buf);

    for (i = 0; i < 8; ++i) {
	store64(buffer + sizeof(S->h[i]) * i, S->h[i]);
    }

    memcpy(out, buffer, S->outlen);
    clear_internal_memory(buffer, sizeof(buffer));
    clear_internal_memory(S->buf, sizeof(S->buf));
    clear_internal_memory(S->h, sizeof(S->h));
    return 0;
}

static inline int argon2_blake2b(void *out, size_t outlen, const void *in, size_t inlen, const void *key, size_t keylen)
{
    argon2_blake2b_state S;
    int ret = -1;

    /* Verify parameters */
    if (NULL == in && inlen > 0) {
	goto fail;
    }

    if (NULL == out || outlen == 0 || outlen > BLAKE2B_OUTBYTES) {
	goto fail;
    }

    if ((NULL == key && keylen > 0) || keylen > BLAKE2B_KEYBYTES) {
	goto fail;
    }

    if (keylen > 0) {
	if (argon2_blake2b_init_key(&S, outlen, key, keylen) < 0) {
	    goto fail;
	}
    } else {
	if (argon2_blake2b_init(&S, outlen) < 0) {
	    goto fail;
	}
    }

    if (argon2_blake2b_update(&S, in, inlen) < 0) {
	goto fail;
    }
    ret = argon2_blake2b_final(&S, out, outlen);

fail:
    clear_internal_memory(&S, sizeof(S));
    return ret;
}

static inline int argon2_blake2b_long(void *pout, size_t outlen, const void *in, size_t inlen) {
    uint8_t *out = (uint8_t *)pout;
    argon2_blake2b_state blake_state;
    uint8_t outlen_bytes[sizeof(uint32_t)] = {0};
    int ret = -1;

    if (outlen > UINT32_MAX) {
	goto fail;
    }

    store32(outlen_bytes, (uint32_t)outlen);

#define TRY(statement)	\
do {			\
ret = statement;	\
if (ret < 0) {	\
goto fail;	\
}			\
} while ((void)0, 0)

    if (outlen <= BLAKE2B_OUTBYTES) {
	TRY(argon2_blake2b_init(&blake_state, outlen));
	TRY(argon2_blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
	TRY(argon2_blake2b_update(&blake_state, in, inlen));
	TRY(argon2_blake2b_final(&blake_state, out, outlen));
    } else {
	uint32_t toproduce;
	uint8_t out_buffer[BLAKE2B_OUTBYTES];
	uint8_t in_buffer[BLAKE2B_OUTBYTES];
	TRY(argon2_blake2b_init(&blake_state, BLAKE2B_OUTBYTES));
	TRY(argon2_blake2b_update(&blake_state, outlen_bytes, sizeof(outlen_bytes)));
	TRY(argon2_blake2b_update(&blake_state, in, inlen));
	TRY(argon2_blake2b_final(&blake_state, out_buffer, BLAKE2B_OUTBYTES));
	memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
	out += BLAKE2B_OUTBYTES / 2;
	toproduce = (uint32_t)outlen - BLAKE2B_OUTBYTES / 2;

	while (toproduce > BLAKE2B_OUTBYTES) {
	    memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
	    TRY(argon2_blake2b(out_buffer, BLAKE2B_OUTBYTES, in_buffer, BLAKE2B_OUTBYTES, NULL, 0));
	    memcpy(out, out_buffer, BLAKE2B_OUTBYTES / 2);
	    out += BLAKE2B_OUTBYTES / 2;
	    toproduce -= BLAKE2B_OUTBYTES / 2;
	}

	memcpy(in_buffer, out_buffer, BLAKE2B_OUTBYTES);
	TRY(argon2_blake2b(out_buffer, toproduce, in_buffer, BLAKE2B_OUTBYTES, NULL, 0));
	memcpy(out, out_buffer, toproduce);
    }
fail:
    clear_internal_memory(&blake_state, sizeof(blake_state));
    return ret;
#undef TRY
}

static inline void fill_first_blocks(uint8_t *blockhash, const argon2_instance_t *instance)
{
    uint32_t l;
    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];

    for (l = 0; l < instance->lanes; ++l) {
	store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 0);
	store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH + 4, l);
	argon2_blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
	load_block(&instance->memory[l * instance->lane_length + 0], blockhash_bytes);

	store32(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, 1);
	argon2_blake2b_long(blockhash_bytes, ARGON2_BLOCK_SIZE, blockhash, ARGON2_PREHASH_SEED_LENGTH);
	load_block(&instance->memory[l * instance->lane_length + 1], blockhash_bytes);
    }
    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
}

static inline void initial_hash(uint8_t *blockhash, argon2_context *context, argon2_type type)
{
    argon2_blake2b_state BlakeHash;
    uint8_t value[sizeof(uint32_t)];

    if (NULL == context || NULL == blockhash) {
	return;
    }

    argon2_blake2b_init(&BlakeHash, ARGON2_PREHASH_DIGEST_LENGTH);

    store32(&value, context->lanes);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->outlen);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->m_cost);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->t_cost);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->version);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, (uint32_t)type);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    store32(&value, context->pwdlen);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->pwd != NULL) {
	argon2_blake2b_update(&BlakeHash, (const uint8_t *)context->pwd, context->pwdlen);

	if (context->flags & ARGON2_FLAG_CLEAR_PASSWORD) {
	    secure_wipe_memory(context->pwd, context->pwdlen);
	    context->pwdlen = 0;
	}
    }

    store32(&value, context->saltlen);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->salt != NULL) {
	argon2_blake2b_update(&BlakeHash, (const uint8_t *)context->salt, context->saltlen);
    }

    store32(&value, context->secretlen);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->secret != NULL) {
	argon2_blake2b_update(&BlakeHash, (const uint8_t *)context->secret, context->secretlen);

	if (context->flags & ARGON2_FLAG_CLEAR_SECRET) {
	    secure_wipe_memory(context->secret, context->secretlen);
	    context->secretlen = 0;
	}
    }

    store32(&value, context->adlen);
    argon2_blake2b_update(&BlakeHash, (const uint8_t *)&value, sizeof(value));

    if (context->ad != NULL) {
	argon2_blake2b_update(&BlakeHash, (const uint8_t *)context->ad, context->adlen);
    }

    argon2_blake2b_final(&BlakeHash, blockhash, ARGON2_PREHASH_DIGEST_LENGTH);
}

static inline int initialize(argon2_instance_t *instance, argon2_context *context)
{
    uint8_t blockhash[ARGON2_PREHASH_SEED_LENGTH];
    int result = NBSCrypto_OK;

    if (instance == NULL || context == NULL){
	return NBSCrypto_ERROR;
    }
    instance->context_ptr = context;

    result = allocate_memory(context, (uint8_t **)&(instance->memory), instance->memory_blocks, sizeof(block));
    if (result != NBSCrypto_OK) {
	return result;
    }

    initial_hash(blockhash, context, instance->type);
    clear_internal_memory(blockhash + ARGON2_PREHASH_DIGEST_LENGTH, ARGON2_PREHASH_SEED_LENGTH - ARGON2_PREHASH_DIGEST_LENGTH);
    fill_first_blocks(blockhash, instance);
    clear_internal_memory(blockhash, ARGON2_PREHASH_SEED_LENGTH);

    return NBSCrypto_OK;
}

static inline void finalize(const argon2_context *context, argon2_instance_t *instance)
{
    if (context != NULL && instance != NULL) {
	block blockhash;
	uint32_t l;

	copy_block(&blockhash, instance->memory + instance->lane_length - 1);

	for (l = 1; l < instance->lanes; ++l) {
	    uint32_t last_block_in_lane =
	    l * instance->lane_length + (instance->lane_length - 1);
	    xor_block(&blockhash, instance->memory + last_block_in_lane);
	}

	{
	    uint8_t blockhash_bytes[ARGON2_BLOCK_SIZE];
	    store_block(blockhash_bytes, &blockhash);
	    argon2_blake2b_long(context->out, context->outlen, blockhash_bytes, ARGON2_BLOCK_SIZE);
	    clear_internal_memory(blockhash.v, ARGON2_BLOCK_SIZE);
	    clear_internal_memory(blockhash_bytes, ARGON2_BLOCK_SIZE);
	}
	free_memory(context, (uint8_t *)instance->memory, instance->memory_blocks, sizeof(block));
    }
}

static inline int b64_byte_to_char(unsigned x)
{
    return (LT(x, 26) & (x + 'A')) |
    (GE(x, 26) & LT(x, 52) & (x + ('a' - 26))) |
    (GE(x, 52) & LT(x, 62) & (x + ('0' - 52))) | (EQ(x, 62) & '+') |
    (EQ(x, 63) & '/');
}

static inline unsigned b64_char_to_byte(int c)
{
    unsigned x;

    x = (GE(c, 'A') & LE(c, 'Z') & (c - 'A')) |
    (GE(c, 'a') & LE(c, 'z') & (c - ('a' - 26))) |
    (GE(c, '0') & LE(c, '9') & (c - ('0' - 52))) | (EQ(c, '+') & 62) |
    (EQ(c, '/') & 63);
    return x | (EQ(x, 0) & (EQ(c, 'A') ^ 0xFF));
}

static inline const char *from_base64(void *dst, size_t *dst_len, const char *src)
{
    size_t len;
    unsigned char *buf;
    unsigned acc, acc_len;

    buf = (unsigned char *)dst;
    len = 0;
    acc = 0;
    acc_len = 0;
    for (;;) {
	unsigned d;

	d = b64_char_to_byte(*src);
	if (d == 0xFF) {
	    break;
	}
	src++;
	acc = (acc << 6) + d;
	acc_len += 6;
	if (acc_len >= 8) {
	    acc_len -= 8;
	    if ((len++) >= *dst_len) {
		return NULL;
	    }
	    *buf++ = (acc >> acc_len) & 0xFF;
	}
    }

    if (acc_len > 4 || (acc & (((unsigned)1 << acc_len) - 1)) != 0) {
	return NULL;
    }
    *dst_len = len;
    return src;
}

static inline size_t to_base64(char *dst, size_t dst_len, const void *src, size_t src_len)
{
    size_t olen;
    const unsigned char *buf;
    unsigned acc, acc_len;

    olen = (src_len / 3) << 2;
    switch (src_len % 3) {
	case 2:
	    olen++;
	case 1:
	    olen += 2;
	    break;
    }
    if (dst_len <= olen) {
	return (size_t)-1;
    }
    acc = 0;
    acc_len = 0;
    buf = (const unsigned char *)src;
    while (src_len-- > 0) {
	acc = (acc << 8) + (*buf++);
	acc_len += 8;
	while (acc_len >= 6) {
	    acc_len -= 6;
	    *dst++ = (char)b64_byte_to_char((acc >> acc_len) & 0x3F);
	}
    }
    if (acc_len > 0) {
	*dst++ = (char)b64_byte_to_char((acc << (6 - acc_len)) & 0x3F);
    }
    *dst++ = 0;
    return olen;
}

static inline const char *decode_decimal(const char *str, unsigned long *v)
{
    const char *orig;
    unsigned long acc;

    acc = 0;
    for (orig = str;; str++) {
	int c;

	c = *str;
	if (c < '0' || c > '9') {
	    break;
	}
	c -= '0';
	if (acc > (ULONG_MAX / 10)) {
	    return NULL;
	}
	acc *= 10;
	if ((unsigned long)c > (ULONG_MAX - acc)) {
	    return NULL;
	}
	acc += (unsigned long)c;
    }
    if (str == orig || (*orig == '0' && str != (orig + 1))) {
	return NULL;
    }
    *v = acc;
    return str;
}

static inline int decode_string(argon2_context *ctx, const char *str, argon2_type type)
{
#define CC(prefix)				\
do {						\
    size_t cc_len = strlen(prefix);		\
    if (strncmp(str, prefix, cc_len) != 0) {	\
	return NBSCrypto_ERROR;			\
    }						\
    str += cc_len;				\
} while ((void)0, 0)

#define CC_opt(prefix, code)			\
do {						\
    size_t cc_len = strlen(prefix);		\
    if (strncmp(str, prefix, cc_len) == 0) {	\
	str += cc_len;				\
	{ code; }				\
    }						\
} while ((void)0, 0)

#define DECIMAL(x)			\
do {					\
    unsigned long dec_x;		\
    str = decode_decimal(str, &dec_x);	\
    if (str == NULL) {			\
	return NBSCrypto_ERROR;		\
    }					\
    (x) = dec_x;			\
} while ((void)0, 0)

#define DECIMAL_U32(x)				\
do {						\
    unsigned long dec_x;			\
    str = decode_decimal(str, &dec_x);		\
    if (str == NULL || dec_x > UINT32_MAX) {	\
	return NBSCrypto_ERROR;			\
    }						\
    (x) = (uint32_t)dec_x;			\
} while ((void)0, 0)

#define BIN(buf, max_len, len)			\
do {						\
    size_t bin_len = (max_len);			\
    str = from_base64(buf, &bin_len, str);	\
    if (str == NULL || bin_len > UINT32_MAX) {	\
	return NBSCrypto_ERROR;			\
    }						\
    (len) = (uint32_t)bin_len;			\
} while ((void)0, 0)

    size_t maxsaltlen = ctx->saltlen;
    size_t maxoutlen = ctx->outlen;
    int validation_result;
    const char* type_string;

    /* We should start with the argon2_type we are using */
    type_string = argon2_type2string(type, 0);
    if (!type_string) {
	return NBSCrypto_ERROR;
    }

    CC("$");
    CC(type_string);

    /* Reading the version number if the default is suppressed */
    ctx->version = ARGON2_VERSION_10;
    CC_opt("$v=", DECIMAL_U32(ctx->version));

    CC("$m=");
    DECIMAL_U32(ctx->m_cost);
    CC(",t=");
    DECIMAL_U32(ctx->t_cost);
    CC(",p=");
    DECIMAL_U32(ctx->lanes);
    ctx->threads = ctx->lanes;

    CC("$");
    BIN(ctx->salt, maxsaltlen, ctx->saltlen);
    CC("$");
    BIN(ctx->out, maxoutlen, ctx->outlen);

    /* The rest of the fields get the default values */
    ctx->secret = NULL;
    ctx->secretlen = 0;
    ctx->ad = NULL;
    ctx->adlen = 0;
    ctx->allocate_cbk = NULL;
    ctx->free_cbk = NULL;
    ctx->flags = ARGON2_DEFAULT_FLAGS;

    /* On return, must have valid context */
    validation_result = validate_inputs(ctx);
    if (validation_result != NBSCrypto_OK) {
	return validation_result;
    }

    /* Can't have any additional characters */
    if (*str == 0) {
	return NBSCrypto_OK;
    } else {
	return NBSCrypto_ERROR;
    }
#undef CC
#undef CC_opt
#undef DECIMAL
#undef BIN
}

static inline int encode_string(char *dst, size_t dst_len, argon2_context *ctx, argon2_type type)
{
#define SS(str)				\
do {					\
    size_t pp_len = strlen(str);	\
    if (pp_len >= dst_len) {		\
	return NBSCrypto_ERROR;		\
    }					\
    memcpy(dst, str, pp_len + 1);	\
    dst += pp_len;			\
    dst_len -= pp_len;			\
} while ((void)0, 0)

#define SX(x)					\
do {						\
    char tmp[30];				\
    sprintf(tmp, "%lu", (unsigned long)(x));	\
    SS(tmp);					\
} while ((void)0, 0)

#define SB(buf, len)					\
do {							\
    size_t sb_len = to_base64(dst, dst_len, buf, len);	\
    if (sb_len == (size_t)-1) {				\
	return NBSCrypto_ERROR;				\
    }							\
    dst += sb_len;					\
    dst_len -= sb_len;					\
} while ((void)0, 0)

    const char* type_string = argon2_type2string(type, 0);
    int validation_result = validate_inputs(ctx);

    if (!type_string) {
	return NBSCrypto_ERROR;
    }

    if (validation_result != NBSCrypto_OK) {
	return validation_result;
    }


    SS("$");
    SS(type_string);

    SS("$v=");
    SX(ctx->version);

    SS("$m=");
    SX(ctx->m_cost);
    SS(",t=");
    SX(ctx->t_cost);
    SS(",p=");
    SX(ctx->lanes);

    SS("$");
    SB(ctx->salt, ctx->saltlen);

    SS("$");
    SB(ctx->out, ctx->outlen);
    return NBSCrypto_OK;

#undef SS
#undef SX
#undef SB
}

static inline int argon2_ctx(argon2_context *context, argon2_type type)
{
    int result = validate_inputs(context);
    uint32_t memory_blocks, segment_length;
    argon2_instance_t instance;

    if (NBSCrypto_OK != result) {
	return result;
    }

    if (Argon2_d != type && Argon2_i != type && Argon2_id != type) {
	return NBSCrypto_ERROR;
    }

    memory_blocks = context->m_cost;

    if (memory_blocks < 2 * ARGON2_SYNC_POINTS * context->lanes) {
	memory_blocks = 2 * ARGON2_SYNC_POINTS * context->lanes;
    }

    segment_length = memory_blocks / (context->lanes * ARGON2_SYNC_POINTS);
    memory_blocks = segment_length * (context->lanes * ARGON2_SYNC_POINTS);

    instance.version = context->version;
    instance.memory = NULL;
    instance.passes = context->t_cost;
    instance.memory_blocks = memory_blocks;
    instance.segment_length = segment_length;
    instance.lane_length = segment_length * ARGON2_SYNC_POINTS;
    instance.lanes = context->lanes;
    instance.threads = context->threads;
    instance.type = type;

    if (instance.threads > instance.lanes) {
	instance.threads = instance.lanes;
    }

    result = initialize(&instance, context);

    if (NBSCrypto_OK != result) {
	return result;
    }

    result = fill_memory_blocks(&instance);

    if (NBSCrypto_OK != result) {
	return result;
    }

    finalize(context, &instance);

    return NBSCrypto_OK;
}

static inline int argon2_compare(const uint8_t *b1, const uint8_t *b2, size_t len)
{
    size_t i;
    uint8_t d = 0U;

    for (i = 0U; i < len; i++) {
	d |= b1[i] ^ b2[i];
    }
    return (int)((1 & ((d - 1) >> 8)) - 1);
}

static inline int argon2_verify_ctx(argon2_context *context, const char *hash, argon2_type type) {
    int ret = argon2_ctx(context, type);
    if (ret != NBSCrypto_OK) {
	return ret;
    }

    if (argon2_compare((uint8_t *)hash, context->out, context->outlen)) {
	return NBSCrypto_ERROR;
    }

    return NBSCrypto_OK;
}

static inline int argon2_verify(const char *encoded, const void *pwd, const size_t pwdlen, argon2_type type)
{
    argon2_context ctx;
    uint8_t *desired_result = NULL;

    int ret = NBSCrypto_OK;

    size_t encoded_len;
    uint32_t max_field_len;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
	return NBSCrypto_ERROR;
    }

    if (encoded == NULL) {
	return NBSCrypto_ERROR;
    }

    encoded_len = strlen(encoded);
    if (encoded_len > UINT32_MAX) {
	return NBSCrypto_ERROR;
    }

    max_field_len = (uint32_t)encoded_len;

    ctx.saltlen = max_field_len;
    ctx.outlen = max_field_len;

    ctx.salt = malloc(ctx.saltlen);
    ctx.out = malloc(ctx.outlen);
    if (!ctx.salt || !ctx.out) {
	ret = NBSCrypto_ERROR;
	goto fail;
    }

    ctx.pwd = (uint8_t *)pwd;
    ctx.pwdlen = (uint32_t)pwdlen;

    ret = decode_string(&ctx, encoded, type);
    if (ret != NBSCrypto_OK) {
	goto fail;
    }

    desired_result = ctx.out;
    ctx.out = malloc(ctx.outlen);
    if (!ctx.out) {
	ret = NBSCrypto_ERROR;
	goto fail;
    }

    ret = argon2_verify_ctx(&ctx, (char *)desired_result, type);
    if (ret != NBSCrypto_OK) {
	goto fail;
    }

fail:
    free(ctx.salt);
    free(ctx.out);
    free(desired_result);

    return ret;
}

static inline size_t b64len(uint32_t len)
{
    size_t olen = ((size_t)len / 3) << 2;

    switch (len % 3) {
	case 2:
	    olen++;
	case 1:
	    olen += 2;
	    break;
    }

    return olen;
}

static inline size_t numlen(uint32_t num)
{
    size_t len = 1;
    while (num >= 10) {
	++len;
	num = num / 10;
    }
    return len;
}




int argon2_hash_password(const uint32_t t_cost, const uint32_t m_cost, const uint32_t parallelism, const void *pwd, const size_t pwdlen, const void *salt, const size_t saltlen, void *hash, const size_t hashlen, char *encoded, const size_t encodedlen, argon2_type type, const uint32_t version)
{
    argon2_context context;
    int result;
    uint8_t *out;

    if (pwdlen > ARGON2_MAX_PWD_LENGTH) {
	return NBSCrypto_ERROR;
    }

    if (saltlen > ARGON2_MAX_SALT_LENGTH) {
	return NBSCrypto_ERROR;
    }

    if (hashlen > ARGON2_MAX_OUTLEN) {
	return NBSCrypto_ERROR;
    }

    if (hashlen < ARGON2_MIN_OUTLEN) {
	return NBSCrypto_ERROR;
    }

    out = malloc(hashlen);
    if (!out) {
	return NBSCrypto_ERROR;
    }

    context.out = (uint8_t *)out;
    context.outlen = (uint32_t)hashlen;
    context.pwd = CONST_CAST(uint8_t *)pwd;
    context.pwdlen = (uint32_t)pwdlen;
    context.salt = CONST_CAST(uint8_t *)salt;
    context.saltlen = (uint32_t)saltlen;
    context.secret = NULL;
    context.secretlen = 0;
    context.ad = NULL;
    context.adlen = 0;
    context.t_cost = t_cost;
    context.m_cost = m_cost;
    context.lanes = parallelism;
    context.threads = parallelism;
    context.allocate_cbk = NULL;
    context.free_cbk = NULL;
    context.flags = ARGON2_DEFAULT_FLAGS;
    context.version = version;

    result = argon2_ctx(&context, type);

    if (result != NBSCrypto_OK) {
	clear_internal_memory(out, hashlen);
	free(out);
	return result;
    }

    if (hash) {
	memcpy(hash, out, hashlen);
    }

    if (encoded && encodedlen) {
	if (encode_string(encoded, encodedlen, &context, type) != NBSCrypto_OK) {
	    clear_internal_memory(out, hashlen);
	    clear_internal_memory(encoded, encodedlen);
	    free(out);
	    return NBSCrypto_ERROR;
	}
    }
    clear_internal_memory(out, hashlen);
    free(out);

    return NBSCrypto_OK;
}

int argon2_verify_password(const unsigned char *key, const unsigned char *hash)
{
    int result;
    int dc1=0;
    char **dt1=NULL;
    argon2_type type = Argon2_i;

    if(key == NULL || hash == NULL){
	return NBSCrypto_ERROR;
    }

    dc1 = splitStr(hash, '$', &dt1);
    if (strcmp("argon2d", dt1[1]) == 0) {
	type = Argon2_d;
    }
    if (strcmp("argon2i", dt1[1]) == 0) {
	type = Argon2_i;
    }
    if (strcmp("argon2id", dt1[1]) == 0) {
	type = Argon2_id;
    }

    result = argon2_verify((const char*)hash, key, strlen((const char*)key), type);
    if (result != NBSCrypto_OK){
	return NBSCrypto_ERROR;
    }

    return NBSCrypto_OK;
}

size_t argon2_encodedlen(uint32_t t_cost, uint32_t m_cost, uint32_t parallelism, uint32_t saltlen, uint32_t hashlen, argon2_type type)
{
    return strlen("$$v=$m=,t=,p=$$") + strlen(argon2_type2string(type, 0)) +
    numlen(t_cost) + numlen(m_cost) + numlen(parallelism) +
    b64len(saltlen) + b64len(hashlen) + numlen(ARGON2_VERSION_NUMBER) + 1;
}

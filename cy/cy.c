/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "cy.h"
#include "_cy_cavl.h"

#include <assert.h>
#include <string.h>

#define BYTE_BITS 8U
#define BYTE_MAX  0xFFU

// #define HEARTBEAT_TOPIC_NAME     "/7509"
#define HEARTBEAT_TOPIC_NAME     "/8191" // TODO FIXME XXX THIS IS ONLY FOR TESTING; the correct name is "/7509"
#define HEARTBEAT_PUB_TIMEOUT_us 1000000UL

/// If a collision is found, do not gossip the topic if it was last seen less than this long ago.
#define GOSSIP_RATE_LIMIT_us 100000UL

static size_t smaller(const size_t a, const size_t b)
{
    return (a < b) ? a : b;
}

#if CY_CONFIG_TRACE

size_t popcount_all(const size_t nbits, const void* x)
{
    size_t               out = 0;
    const uint8_t* const p   = (const uint8_t*)x;
    for (size_t i = 0; i < (nbits / 8U); i++) {
        out += (size_t)__builtin_popcount(p[i]);
    }
    return out;
}

#endif

// ----------------------------------------  CRC-64/WE  ----------------------------------------

#define CRC64WE_INITIAL UINT64_MAX

static const uint64_t crc64we_table[256] = {
    0x0000000000000000ULL, 0x42F0E1EBA9EA3693ULL, 0x85E1C3D753D46D26ULL, 0xC711223CFA3E5BB5ULL, 0x493366450E42ECDFULL,
    0x0BC387AEA7A8DA4CULL, 0xCCD2A5925D9681F9ULL, 0x8E224479F47CB76AULL, 0x9266CC8A1C85D9BEULL, 0xD0962D61B56FEF2DULL,
    0x17870F5D4F51B498ULL, 0x5577EEB6E6BB820BULL, 0xDB55AACF12C73561ULL, 0x99A54B24BB2D03F2ULL, 0x5EB4691841135847ULL,
    0x1C4488F3E8F96ED4ULL, 0x663D78FF90E185EFULL, 0x24CD9914390BB37CULL, 0xE3DCBB28C335E8C9ULL, 0xA12C5AC36ADFDE5AULL,
    0x2F0E1EBA9EA36930ULL, 0x6DFEFF5137495FA3ULL, 0xAAEFDD6DCD770416ULL, 0xE81F3C86649D3285ULL, 0xF45BB4758C645C51ULL,
    0xB6AB559E258E6AC2ULL, 0x71BA77A2DFB03177ULL, 0x334A9649765A07E4ULL, 0xBD68D2308226B08EULL, 0xFF9833DB2BCC861DULL,
    0x388911E7D1F2DDA8ULL, 0x7A79F00C7818EB3BULL, 0xCC7AF1FF21C30BDEULL, 0x8E8A101488293D4DULL, 0x499B3228721766F8ULL,
    0x0B6BD3C3DBFD506BULL, 0x854997BA2F81E701ULL, 0xC7B97651866BD192ULL, 0x00A8546D7C558A27ULL, 0x4258B586D5BFBCB4ULL,
    0x5E1C3D753D46D260ULL, 0x1CECDC9E94ACE4F3ULL, 0xDBFDFEA26E92BF46ULL, 0x990D1F49C77889D5ULL, 0x172F5B3033043EBFULL,
    0x55DFBADB9AEE082CULL, 0x92CE98E760D05399ULL, 0xD03E790CC93A650AULL, 0xAA478900B1228E31ULL, 0xE8B768EB18C8B8A2ULL,
    0x2FA64AD7E2F6E317ULL, 0x6D56AB3C4B1CD584ULL, 0xE374EF45BF6062EEULL, 0xA1840EAE168A547DULL, 0x66952C92ECB40FC8ULL,
    0x2465CD79455E395BULL, 0x3821458AADA7578FULL, 0x7AD1A461044D611CULL, 0xBDC0865DFE733AA9ULL, 0xFF3067B657990C3AULL,
    0x711223CFA3E5BB50ULL, 0x33E2C2240A0F8DC3ULL, 0xF4F3E018F031D676ULL, 0xB60301F359DBE0E5ULL, 0xDA050215EA6C212FULL,
    0x98F5E3FE438617BCULL, 0x5FE4C1C2B9B84C09ULL, 0x1D14202910527A9AULL, 0x93366450E42ECDF0ULL, 0xD1C685BB4DC4FB63ULL,
    0x16D7A787B7FAA0D6ULL, 0x5427466C1E109645ULL, 0x4863CE9FF6E9F891ULL, 0x0A932F745F03CE02ULL, 0xCD820D48A53D95B7ULL,
    0x8F72ECA30CD7A324ULL, 0x0150A8DAF8AB144EULL, 0x43A04931514122DDULL, 0x84B16B0DAB7F7968ULL, 0xC6418AE602954FFBULL,
    0xBC387AEA7A8DA4C0ULL, 0xFEC89B01D3679253ULL, 0x39D9B93D2959C9E6ULL, 0x7B2958D680B3FF75ULL, 0xF50B1CAF74CF481FULL,
    0xB7FBFD44DD257E8CULL, 0x70EADF78271B2539ULL, 0x321A3E938EF113AAULL, 0x2E5EB66066087D7EULL, 0x6CAE578BCFE24BEDULL,
    0xABBF75B735DC1058ULL, 0xE94F945C9C3626CBULL, 0x676DD025684A91A1ULL, 0x259D31CEC1A0A732ULL, 0xE28C13F23B9EFC87ULL,
    0xA07CF2199274CA14ULL, 0x167FF3EACBAF2AF1ULL, 0x548F120162451C62ULL, 0x939E303D987B47D7ULL, 0xD16ED1D631917144ULL,
    0x5F4C95AFC5EDC62EULL, 0x1DBC74446C07F0BDULL, 0xDAAD56789639AB08ULL, 0x985DB7933FD39D9BULL, 0x84193F60D72AF34FULL,
    0xC6E9DE8B7EC0C5DCULL, 0x01F8FCB784FE9E69ULL, 0x43081D5C2D14A8FAULL, 0xCD2A5925D9681F90ULL, 0x8FDAB8CE70822903ULL,
    0x48CB9AF28ABC72B6ULL, 0x0A3B7B1923564425ULL, 0x70428B155B4EAF1EULL, 0x32B26AFEF2A4998DULL, 0xF5A348C2089AC238ULL,
    0xB753A929A170F4ABULL, 0x3971ED50550C43C1ULL, 0x7B810CBBFCE67552ULL, 0xBC902E8706D82EE7ULL, 0xFE60CF6CAF321874ULL,
    0xE224479F47CB76A0ULL, 0xA0D4A674EE214033ULL, 0x67C58448141F1B86ULL, 0x253565A3BDF52D15ULL, 0xAB1721DA49899A7FULL,
    0xE9E7C031E063ACECULL, 0x2EF6E20D1A5DF759ULL, 0x6C0603E6B3B7C1CAULL, 0xF6FAE5C07D3274CDULL, 0xB40A042BD4D8425EULL,
    0x731B26172EE619EBULL, 0x31EBC7FC870C2F78ULL, 0xBFC9838573709812ULL, 0xFD39626EDA9AAE81ULL, 0x3A28405220A4F534ULL,
    0x78D8A1B9894EC3A7ULL, 0x649C294A61B7AD73ULL, 0x266CC8A1C85D9BE0ULL, 0xE17DEA9D3263C055ULL, 0xA38D0B769B89F6C6ULL,
    0x2DAF4F0F6FF541ACULL, 0x6F5FAEE4C61F773FULL, 0xA84E8CD83C212C8AULL, 0xEABE6D3395CB1A19ULL, 0x90C79D3FEDD3F122ULL,
    0xD2377CD44439C7B1ULL, 0x15265EE8BE079C04ULL, 0x57D6BF0317EDAA97ULL, 0xD9F4FB7AE3911DFDULL, 0x9B041A914A7B2B6EULL,
    0x5C1538ADB04570DBULL, 0x1EE5D94619AF4648ULL, 0x02A151B5F156289CULL, 0x4051B05E58BC1E0FULL, 0x87409262A28245BAULL,
    0xC5B073890B687329ULL, 0x4B9237F0FF14C443ULL, 0x0962D61B56FEF2D0ULL, 0xCE73F427ACC0A965ULL, 0x8C8315CC052A9FF6ULL,
    0x3A80143F5CF17F13ULL, 0x7870F5D4F51B4980ULL, 0xBF61D7E80F251235ULL, 0xFD913603A6CF24A6ULL, 0x73B3727A52B393CCULL,
    0x31439391FB59A55FULL, 0xF652B1AD0167FEEAULL, 0xB4A25046A88DC879ULL, 0xA8E6D8B54074A6ADULL, 0xEA16395EE99E903EULL,
    0x2D071B6213A0CB8BULL, 0x6FF7FA89BA4AFD18ULL, 0xE1D5BEF04E364A72ULL, 0xA3255F1BE7DC7CE1ULL, 0x64347D271DE22754ULL,
    0x26C49CCCB40811C7ULL, 0x5CBD6CC0CC10FAFCULL, 0x1E4D8D2B65FACC6FULL, 0xD95CAF179FC497DAULL, 0x9BAC4EFC362EA149ULL,
    0x158E0A85C2521623ULL, 0x577EEB6E6BB820B0ULL, 0x906FC95291867B05ULL, 0xD29F28B9386C4D96ULL, 0xCEDBA04AD0952342ULL,
    0x8C2B41A1797F15D1ULL, 0x4B3A639D83414E64ULL, 0x09CA82762AAB78F7ULL, 0x87E8C60FDED7CF9DULL, 0xC51827E4773DF90EULL,
    0x020905D88D03A2BBULL, 0x40F9E43324E99428ULL, 0x2CFFE7D5975E55E2ULL, 0x6E0F063E3EB46371ULL, 0xA91E2402C48A38C4ULL,
    0xEBEEC5E96D600E57ULL, 0x65CC8190991CB93DULL, 0x273C607B30F68FAEULL, 0xE02D4247CAC8D41BULL, 0xA2DDA3AC6322E288ULL,
    0xBE992B5F8BDB8C5CULL, 0xFC69CAB42231BACFULL, 0x3B78E888D80FE17AULL, 0x7988096371E5D7E9ULL, 0xF7AA4D1A85996083ULL,
    0xB55AACF12C735610ULL, 0x724B8ECDD64D0DA5ULL, 0x30BB6F267FA73B36ULL, 0x4AC29F2A07BFD00DULL, 0x08327EC1AE55E69EULL,
    0xCF235CFD546BBD2BULL, 0x8DD3BD16FD818BB8ULL, 0x03F1F96F09FD3CD2ULL, 0x41011884A0170A41ULL, 0x86103AB85A2951F4ULL,
    0xC4E0DB53F3C36767ULL, 0xD8A453A01B3A09B3ULL, 0x9A54B24BB2D03F20ULL, 0x5D45907748EE6495ULL, 0x1FB5719CE1045206ULL,
    0x919735E51578E56CULL, 0xD367D40EBC92D3FFULL, 0x1476F63246AC884AULL, 0x568617D9EF46BED9ULL, 0xE085162AB69D5E3CULL,
    0xA275F7C11F7768AFULL, 0x6564D5FDE549331AULL, 0x279434164CA30589ULL, 0xA9B6706FB8DFB2E3ULL, 0xEB46918411358470ULL,
    0x2C57B3B8EB0BDFC5ULL, 0x6EA7525342E1E956ULL, 0x72E3DAA0AA188782ULL, 0x30133B4B03F2B111ULL, 0xF7021977F9CCEAA4ULL,
    0xB5F2F89C5026DC37ULL, 0x3BD0BCE5A45A6B5DULL, 0x79205D0E0DB05DCEULL, 0xBE317F32F78E067BULL, 0xFCC19ED95E6430E8ULL,
    0x86B86ED5267CDBD3ULL, 0xC4488F3E8F96ED40ULL, 0x0359AD0275A8B6F5ULL, 0x41A94CE9DC428066ULL, 0xCF8B0890283E370CULL,
    0x8D7BE97B81D4019FULL, 0x4A6ACB477BEA5A2AULL, 0x089A2AACD2006CB9ULL, 0x14DEA25F3AF9026DULL, 0x562E43B4931334FEULL,
    0x913F6188692D6F4BULL, 0xD3CF8063C0C759D8ULL, 0x5DEDC41A34BBEEB2ULL, 0x1F1D25F19D51D821ULL, 0xD80C07CD676F8394ULL,
    0x9AFCE626CE85B507ULL,
};

static uint64_t crc64we_string(const char* str)
{
    assert(str != NULL);
    uint64_t crc = CRC64WE_INITIAL;
    while (*str != '\0') {
        crc = crc64we_table[((uint8_t)*str) ^ (crc >> 56U)] ^ (crc << 8U);
        ++str;
    }
    return crc;
}

// ----------------------------------------  AVL TREE UTILITIES  ----------------------------------------

// hash index tree

static int8_t cavl_predicate_topic_hash_raw(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const uint64_t                 outer = *(uint64_t*)user_reference;
    const struct cy_topic_t* const inner = (const struct cy_topic_t*)node;
    if (outer == inner->hash) {
        return 0;
    }
    return (outer >= inner->hash) ? +1 : -1;
}

static int8_t cavl_predicate_topic_hash(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    return cavl_predicate_topic_hash_raw(&(((struct cy_topic_t*)user_reference)->hash), node);
}

static struct cy_tree_t* cavl_factory_topic_hash(void* const user_reference)
{
    return &((struct cy_topic_t*)user_reference)->index_hash;
}

// subject-ID index tree

static int8_t cavl_predicate_topic_subject_id_raw(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const uint16_t                 outer = *(uint16_t*)user_reference;
    const struct cy_topic_t* const inner =
      (const struct cy_topic_t*)(((const char*)node) - offsetof(struct cy_topic_t, index_subject_id));
    if (outer == inner->subject_id) {
        return 0;
    }
    return (outer >= inner->subject_id) ? +1 : -1;
}

static int8_t cavl_predicate_topic_subject_id(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    return cavl_predicate_topic_subject_id_raw(&(((struct cy_topic_t*)user_reference)->subject_id), node);
}

static struct cy_tree_t* cavl_factory_topic_subject_id(void* const user_reference)
{
    return &((struct cy_topic_t*)user_reference)->index_subject_id;
}

// gossip time index tree

/// Gossip times do not have to be unique, so this comparator never returns 0.
static int8_t cavl_predicate_topic_gossip_time(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const struct cy_topic_t* const outer = (struct cy_topic_t*)user_reference;
    const struct cy_topic_t* const inner =
      (const struct cy_topic_t*)(((const char*)node) - offsetof(struct cy_topic_t, index_gossip_time));
    return (outer->last_gossip_us >= inner->last_gossip_us) ? +1 : -1;
}

static struct cy_tree_t* cavl_factory_topic_gossip_time(void* const user_reference)
{
    return &((struct cy_topic_t*)user_reference)->index_gossip_time;
}

// ----------------------------------------  RANDOM NUMBERS  ----------------------------------------

static _Thread_local uint64_t g_splitmix64_state;

/// The standard splitmix64 implementation.
static uint64_t splitmix64(void)
{
    uint64_t z = (g_splitmix64_state += 0x9e3779b97f4a7c15U);
    z          = (z ^ (z >> 30U)) * 0xbf58476d1ce4e5b9U;
    z          = (z ^ (z >> 27U)) * 0x94d049bb133111ebU;
    return z ^ (z >> 31U);
}

/// The limits are inclusive. Returns min unless min < max.
static uint64_t random_uint(const uint64_t min, const uint64_t max)
{
    if (min < max) {
        return (splitmix64() % (max - min)) + min;
    }
    return min;
}

// ----------------------------------------  NODE ID ALLOCATION  ----------------------------------------

// ReSharper disable CppDFAConstantParameter

/// A Bloom filter is a set-only structure so there is no way to clear a bit after it has been set.
/// It is only possible to purge the entire filter state.
static void bloom64_set(const size_t bloom_capacity, uint64_t* const bloom, const size_t value)
{
    assert(bloom != NULL);
    const size_t index = value % bloom_capacity;
    bloom[index / 64U] |= (1ULL << (index % 64U));
}

static bool bloom64_get(const size_t bloom_capacity, const uint64_t* const bloom, const size_t value)
{
    assert(bloom != NULL);
    const size_t index = value % bloom_capacity;
    return (bloom[index / 64U] & (1ULL << (index % 64U))) != 0;
}

static void bloom64_purge(const size_t bloom_capacity, uint64_t* const bloom)
{
    assert(bloom != NULL);
    for (size_t i = 0; i < (bloom_capacity + 63U) / 64U; i++) {
        bloom[i] = 0ULL; // I suppose this is better than memset cuz we're aligned to 64 bits.
    }
}

/// This is guaranteed to return a valid node-ID. If the Bloom filter is not full, an unoccupied node-ID will be
/// chosen, and the corresponding entry in the filter will be set. If the filter is full, a random node-ID will be
/// chosen, which can only happen if more than filter capacity nodes are currently online.
/// The complexity is constant, independent of the filter occupancy.
static uint16_t allocate_node_id(const size_t bloom_capacity, const uint64_t* const bloom, const uint16_t node_id_max)
{
    // The algorithm is hierarchical: find a 64-bit word that has at least one zero bit, then find a zero bit in it.
    // This somewhat undermines the randomness of the result, but it is fast and simple.
    const size_t num_words  = (smaller(node_id_max, bloom_capacity) + 63U) / 64U;
    size_t       word_index = (size_t)random_uint(0U, num_words - 1U);
    for (size_t i = 0; i < num_words; i++) {
        if (bloom[word_index] != UINT64_MAX) {
            break;
        }
        word_index = (word_index + 1U) % num_words;
    }
    const uint64_t word = bloom[word_index];
    if (word == UINT64_MAX) {
        return (uint16_t)random_uint(0U, node_id_max); // The filter is full, fallback to random node-ID.
    }

    // Now we have a word with at least one zero bit. Find a random zero bit in it.
    uint8_t bit_index = (uint8_t)random_uint(0U, 63U);
    assert(word != UINT64_MAX);
    while ((word & (1ULL << bit_index)) != 0) { // guaranteed to terminate, see above.
        bit_index = (bit_index + 1U) % 64U;
    }

    // Now we have some valid node-ID. Recall that the Bloom filter maps multiple values to the same bit.
    // This means that we can increase randomness by multiplying the node-ID by a multiple of the Bloom filter period.
    size_t node_id = (word_index * 64U) + bit_index;
    assert(node_id < node_id_max);
    assert(bloom64_get(bloom_capacity, bloom, node_id) == false);
    const size_t oversubscription = (size_t)(node_id_max / bloom_capacity);
    if (oversubscription > 0) {
        node_id += (size_t)random_uint(0, oversubscription) * bloom_capacity;
    }
    assert(node_id < node_id_max);
    assert(bloom64_get(bloom_capacity, bloom, node_id) == false);
    bloom64_set(bloom_capacity, (uint64_t*)bloom, node_id);
    return (uint16_t)node_id;
}

// ReSharper restore CppDFAConstantParameter

// ----------------------------------------  TOPIC HASH  ----------------------------------------

/// Returns CY_SUBJECT_ID_INVALID if the string is not a valid pinned subject-ID form.
/// Pinned topic names must have only canonical names to ensure that no two topic names map to the same subject-ID.
/// The only requirement to ensure this is that there must be no leading zeros in the number.
static uint16_t parse_pinned(const char* s)
{
    if ((s == NULL) || (*s != '/')) {
        return CY_SUBJECT_ID_INVALID;
    }
    s++;
    if ((*s == '\0') || (*s == '0')) { // Leading zeroes not allowed; only canonical form is accepted.
        return CY_SUBJECT_ID_INVALID;
    }
    uint32_t out = 0U;
    while (*s != '\0') {
        if ((*s < '0') || (*s > '9')) {
            return CY_SUBJECT_ID_INVALID;
        }
        out = (out * 10U) + (uint8_t)(*s++ - '0');
        if (out >= CY_TOTAL_SUBJECT_COUNT) {
            return CY_SUBJECT_ID_INVALID;
        }
    }
    return (uint16_t)out;
}

/// Topic hash is the cornerstone of the protocol.
static uint64_t topic_hash(const char* const name, bool* const out_pinned)
{
    uint64_t   hash = parse_pinned(name);
    const bool stat = hash < CY_TOTAL_SUBJECT_COUNT;
    if (!stat) {
        hash = crc64we_string(name);
    }
    if (out_pinned != NULL) {
        *out_pinned = stat;
    }
    return hash;
}

// ----------------------------------------  HEARTBEAT IO  ----------------------------------------

struct topic_gossip_t
{
    uint64_t lamport_clock;
    uint64_t owner_uid;
    uint16_t value;
    uint16_t _padding_a;
    uint32_t _padding_b;
    uint8_t  name_length;
    char     name[CY_TOPIC_NAME_MAX];
};
static_assert(sizeof(struct topic_gossip_t) == 8 + 4 + 4 + 2 + 6 + 1 + CY_TOPIC_NAME_MAX, "bad layout");

/// We could have used Nunavut, but we only need a single message and it's very simple, so we do it manually.
struct heartbeat_t
{
    uint32_t              uptime;
    uint16_t              _padding_a;
    uint16_t              user_word;
    uint64_t              uid;
    struct topic_gossip_t topic_gossip;
};
static_assert(sizeof(struct heartbeat_t) == 144, "bad layout");

static struct heartbeat_t make_heartbeat(const uint64_t    uptime_us,
                                         const uint64_t    uid,
                                         const uint64_t    lamport_clock,
                                         const uint64_t    owner_uid,
                                         const uint16_t    value,
                                         const size_t      name_len,
                                         const char* const name)
{
    assert(name_len <= CY_TOPIC_NAME_MAX);
    struct heartbeat_t obj = {
        .uptime = (uint32_t)(uptime_us / 1000000U),
        .uid = uid,
        .topic_gossip =
            {
                .lamport_clock = lamport_clock,
                .owner_uid     = owner_uid,
                .value         = value,
                .name_length   = (uint8_t)name_len,
            },
    };
    memcpy(obj.topic_gossip.name, name, name_len);
    return obj;
}

static size_t get_heartbeat_size(const struct heartbeat_t* const obj)
{
    assert(obj != NULL);
    assert(obj->topic_gossip.name_length <= CY_TOPIC_NAME_MAX);
    return sizeof(*obj) - (CY_TOPIC_NAME_MAX - obj->topic_gossip.name_length);
}

/// log(N) index update requires removal and reinsertion.
static void update_last_gossip_time(struct cy_topic_t* const topic, const uint64_t ts_us)
{
    cavlRemove(&topic->cy->topics_by_gossip_time, &topic->index_gossip_time);
    topic->last_gossip_us              = ts_us;
    const struct cy_tree_t* const tree = cavlSearch(
      &topic->cy->topics_by_gossip_time, topic, cavl_predicate_topic_gossip_time, cavl_factory_topic_gossip_time);
    assert(tree == &topic->index_gossip_time);
}

static cy_err_t publish_heartbeat(struct cy_topic_t* const topic, const uint64_t now)
{
    assert(topic != NULL);
    const struct cy_t* const cy = topic->cy;

    // Construct the heartbeat message.
    // TODO: communicate how the topic is used: pub/sub, some other metadata?
    const struct heartbeat_t msg = make_heartbeat(now - cy->started_at_us,
                                                  cy->uid,
                                                  topic->lamport_clock,
                                                  topic->owner_uid,
                                                  topic->subject_id,
                                                  topic->name_length,
                                                  topic->name);
    const size_t             msz = get_heartbeat_size(&msg);
    assert(msz <= sizeof(msg));
    assert(msg.topic_gossip.name_length <= CY_TOPIC_NAME_MAX);
    const struct cy_payload_t payload = { .data = &msg, .size = msz }; // FIXME serialization

    // Publish the message.
    const cy_err_t pub_res = cy->transport.publish(cy->heartbeat_topic, now + HEARTBEAT_PUB_TIMEOUT_us, payload);
    cy->heartbeat_topic->pub_transfer_id++;

    // Update gossip time even if failed so we don't get stuck publishing same gossip if error reporting is broken.
    update_last_gossip_time(topic, now);
    return pub_res;
}

// ReSharper disable once CppParameterMayBeConstPtrOrRef
static void on_heartbeat(struct cy_subscription_t* const sub,
                         const uint64_t                  ts_us,
                         const struct cy_transfer_meta_t transfer,
                         const struct cy_payload_t       payload)
{
    assert(sub != NULL);
    assert(payload.data != NULL);
    assert(payload.size <= sizeof(struct heartbeat_t));
    if (payload.size < (sizeof(struct heartbeat_t) - CY_TOPIC_NAME_MAX)) {
        return; // This is an old uavcan.node.Heartbeat.1 message, ignore it because it has no CRDT gossip data.
    }
    (void)ts_us;
    (void)transfer;

    // Deserialize the message.
    // TODO: this is not a proper deserialization, we need to do it properly.
    struct heartbeat_t heartbeat = { 0 };
    memcpy(&heartbeat, payload.data, smaller(payload.size, sizeof(heartbeat)));
    const struct topic_gossip_t* const gos = &heartbeat.topic_gossip;
    if ((gos->name_length == 0) || (gos->name_length > CY_TOPIC_NAME_MAX)) {
        return; // Malformed message.
    }

    // Check the kind of the resource. Canonical topic names must begin with a slash.
    if (gos->name[0] != '/') {
        return; // Not a topic.
    }

    // Find the topic in our local database.
    struct cy_t* const cy    = sub->topic->cy;
    struct cy_topic_t* topic = cy_topic_find_by_name(cy, gos->name);
    if (topic == NULL) { // We don't know this topic, but we still need to check for a subject-ID collision.
        topic = cy_topic_find_by_subject_id(cy, gos->value);
        if (topic == NULL) {
            return; // We are not using this subject-ID, no collision.
        }
        // TODO: resolve divergences. FOCUS HERE
        return;
    }
    assert(topic->name_length == gos->name_length);

    // This will prevent us from publishing this topic soon again because the network just saw it.
    update_last_gossip_time(topic, ts_us);

    // If the gossiped state matches our local replica, nothing needs to be done.
    // This is the most common case that occurs all the time in a stable network, so we need to optimize for it.
    if ((topic->lamport_clock == gos->lamport_clock) && //
        (topic->owner_uid == gos->owner_uid) &&         //
        (topic->subject_id == gos->value)) {
        return; // No divergence, nothing to do.
    }

    // TODO: resolve divergences. FOCUS HERE
}

// ----------------------------------------  PUBLIC API  ----------------------------------------

cy_err_t cy_new(struct cy_t* const             cy,
                const uint64_t                 uid,
                const uint16_t                 node_id,
                const uint16_t                 node_id_max,
                const char* const              namespace_,
                struct cy_topic_t* const       heartbeat_topic,
                const cy_now_t                 now,
                const struct cy_transport_io_t transport_io)
{
    assert(cy != NULL);
    assert(uid != 0);

    // This is fine even if multiple nodes run locally!
    g_splitmix64_state ^= uid;

    // Init the object.
    memset(cy, 0, sizeof(*cy));
    cy->uid         = uid;
    cy->node_id     = (node_id <= node_id_max) ? node_id : CY_NODE_ID_INVALID;
    cy->node_id_max = node_id_max;

    cy->namespace_length = (namespace_ == NULL) ? 0 : smaller(strlen(namespace_), CY_NAMESPACE_NAME_MAX);
    if (cy->namespace_length > 0) {
        memcpy(cy->namespace_, namespace_, cy->namespace_length);
        cy->namespace_[CY_NAMESPACE_NAME_MAX] = '\0';
    } else {
        cy->namespace_length = 1;
        cy->namespace_[0]    = '~';
        cy->namespace_[1]    = '\0';
    }
    cy->user                  = NULL;
    cy->now                   = now;
    cy->transport             = transport_io;
    cy->heartbeat_topic       = heartbeat_topic;
    cy->topics_by_hash        = NULL;
    cy->topics_by_subject_id  = NULL;
    cy->topics_by_gossip_time = NULL;
    cy->topic_count           = 0;

    // Postpone calling the functions until after the object is set up.
    cy->started_at_us = cy->now(cy);

    bloom64_purge(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom);

    // If a node-ID is given explicitly, we want to publish our heartbeat ASAP to speed up network convergence
    // and to claim the address. If we are not given a node-ID, we need to first listen to the network.
    cy->heartbeat_period_us = CY_HEARTBEAT_PERIOD_DEFAULT_us;
    cy->heartbeat_next_us   = cy->started_at_us;
    cy_err_t res            = 0;
    if (cy->node_id > cy->node_id_max) {
        cy->heartbeat_next_us += random_uint(CY_START_DELAY_MIN_us, CY_START_DELAY_MAX_us);
    } else {
        bloom64_set(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom, cy->node_id);
        res = cy->transport.set_node_id(cy);
    }

    // Register the heartbeat topic and subscribe to it.
    if (res >= 0) {
        const bool topic_ok = cy_topic_new(cy, cy->heartbeat_topic, HEARTBEAT_TOPIC_NAME);
        assert(topic_ok);
        res = cy_subscribe(cy->heartbeat_topic,
                           &cy->heartbeat_sub,
                           sizeof(struct heartbeat_t),
                           CY_TRANSFER_ID_TIMEOUT_DEFAULT_us,
                           &on_heartbeat);
        if (res < 0) {
            cy_topic_destroy(cy->heartbeat_topic);
        }
    }
    return res;
}

void cy_ingest(struct cy_topic_t* const        topic,
               const uint64_t                  timestamp_us,
               const struct cy_transfer_meta_t metadata,
               const struct cy_payload_t       payload)
{
    assert(topic != NULL);
    struct cy_t* const cy = topic->cy;

    // We snoop on all transfers to update the node-ID occupancy Bloom filter.
    // If we don't have a node-ID and this is a new Bloom entry, follow CSMA/CD: add random wait.
    // The point is to reduce the chances of multiple nodes appearing simultaneously and claiming same node-IDs.
    if ((cy->node_id > cy->node_id_max) &&
        !bloom64_get(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom, metadata.remote_node_id)) {
        // The mean extra time is chosen to be simply one heartbeat period.
        cy->heartbeat_next_us += random_uint(0, 2 * CY_HEARTBEAT_PERIOD_DEFAULT_us);
        CY_TRACE(cy,
                 "Discovered neighbor %u publishing on '%s'@%u. New Bloom popcount %zu",
                 metadata.remote_node_id,
                 topic->name,
                 topic->subject_id,
                 popcount_all(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom) + 1U);
    }
    bloom64_set(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom, metadata.remote_node_id);

    // Simply invoke all callbacks in the subscription list.
    struct cy_subscription_t* sub = topic->sub_list;
    while (sub != NULL) {
        assert(sub->topic == topic);
        struct cy_subscription_t* const next = sub->next; // In case the callback deletes this subscription.
        if (sub->callback != NULL) {
            sub->callback(sub, timestamp_us, metadata, payload);
        }
        sub = next;
    }
}

cy_err_t cy_heartbeat(struct cy_t* const cy)
{
    const uint64_t now = cy->now(cy);
    if (now < cy->heartbeat_next_us) {
        return 0;
    }

    // If it is time to publish a heartbeat but we still don't have a node-ID, it means that it is time to allocate!
    cy_err_t res = 0;
    if (cy->node_id >= cy->node_id_max) {
        cy->node_id = allocate_node_id(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom, cy->node_id_max);
        assert(cy->node_id <= cy->node_id_max);
        res = cy->transport.set_node_id(cy);
        CY_TRACE(cy,
                 "Allocated node-ID %u; Bloom popcount %zu; set_node_id()->%d",
                 cy->node_id,
                 popcount_all(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom),
                 res);
    }
    assert(cy->node_id <= cy->node_id_max);
    if (res < 0) {
        return res; // Failed to set node-ID, bail out. Will try again next time.
    }

    // Find the next topic to gossip.
    const struct cy_tree_t* const t = cavlFindExtremum(cy->topics_by_gossip_time, false);
    assert(t != NULL); // We always have at least the heartbeat topic.
    struct cy_topic_t* const tp = (struct cy_topic_t*)(((char*)t) - offsetof(struct cy_topic_t, index_gossip_time));
    assert(tp->cy == cy);

    // If this heartbeat failed to publish, we simply give up and move on to try again in the next period.
    res = publish_heartbeat(tp, now);
    cy->heartbeat_next_us += cy->heartbeat_period_us; // Do not accumulate heartbeat phase slip!

    return res;
}

void cy_notify_discriminator_collision(struct cy_topic_t* const topic)
{
    // Schedule the topic for gossiping ASAP, unless it is already scheduled.
    if ((topic != NULL) && (topic->last_gossip_us > 0)) {
        CY_TRACE(topic->cy,
                 "Discriminator collision on '%s'@%u. Scheduling to gossip on next heartbeat.",
                 topic->name,
                 topic->subject_id);
        struct cy_tree_t** const index = &topic->cy->topics_by_gossip_time;
        cavlRemove(index, &topic->index_gossip_time);
        topic->last_gossip_us = 0; // Topics with the same time will be ordered FIFO -- the tree is stable.
        (void)cavlSearch(index, topic, cavl_predicate_topic_gossip_time, cavl_factory_topic_gossip_time);
        // We could subtract the heartbeat period from the next heartbeat time to make it come out sooner,
        // but this way we would generate unpredictable network loading. We probably don't want that.
    }
}

void cy_notify_node_id_collision(struct cy_t* const cy)
{
    assert(cy != NULL);
    if (cy->node_id > cy->node_id_max) {
        return; // We are not using a node-ID, nothing to do.
    }
    CY_TRACE(cy,
             "Node-ID collision on %u. Bloom purge with popcount %zu",
             cy->node_id,
             popcount_all(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom));
    // We must reset the Bloom filter because there may be tombstones in it.
    // It will be repopulated afresh during the delay we set above.
    bloom64_purge(CY_NODE_ID_BLOOM_CAPACITY, cy->node_id_bloom);
    // Restart the node-ID allocation process.
    cy->node_id = CY_NODE_ID_INVALID;
    cy->heartbeat_next_us += random_uint(CY_START_DELAY_MIN_us, CY_START_DELAY_MAX_us);
    cy->transport.clear_node_id(cy);
}

bool cy_topic_new(struct cy_t* const cy, struct cy_topic_t* const topic, const char* const name)
{
    assert(cy != NULL);
    assert(topic != NULL);
    assert(name != NULL);
    memset(topic, 0, sizeof(*topic));
    topic->cy = cy;

    // TODO: prefix the namespace unless the topic name starts with "/".
    // TODO: expand ~ to "/vvvv/pppp/iiiiiiii/"
    // TODO: canonicalize the topic name (repeated/trailing slash, strip whitespace, etc.).
    topic->name_length = strlen(name);
    memcpy(topic->name, name, smaller(topic->name_length, CY_TOPIC_NAME_MAX));
    topic->name[CY_TOPIC_NAME_MAX] = '\0';
    bool pinned                    = false;
    topic->hash                    = topic_hash(name, &pinned);

    /// Schedule the first gossiping time with a simple optimization.
    /// If this is an ordinary topic, we want this to happen ASAP to minimize collisions.
    /// If this is a pinned topic, we can deprioritize it because we are not responsible for collision resolution
    /// and we don't want to delay the other topics.
    topic->last_gossip_us = pinned ? cy->now(cy) : 0;

    // Declare ourselves as the owner of the topic. We may get kicked out later if there's a collision and we lose.
    topic->lamport_clock = 1; // By convention, the first valid record starts at 1.
    topic->owner_uid     = topic->cy->uid;

    topic->user            = NULL;
    topic->pub_transfer_id = 0;
    topic->pub_priority    = cy_prio_nominal;
    topic->sub_list        = NULL;
    topic->sub_active      = false;

    bool ok = (topic->name_length > 0) && (topic->name_length <= CY_TOPIC_NAME_MAX) && //
              (cy->topic_count < CY_TOPIC_SUBJECT_COUNT);

    // Insert the new topic into the name index tree. If it's not unique, bail out.
    if (ok) {
        const struct cy_tree_t* const res_tree =
          cavlSearch(&cy->topics_by_hash, topic, &cavl_predicate_topic_hash, &cavl_factory_topic_hash);
        assert(res_tree != NULL);
        ok = res_tree == &topic->index_hash; // Reject if the name is already taken.
    }

    // Allocate a subject-ID for the topic and insert it into the subject index tree.
    // The CAVL library has a convenient "find or create" function that suits this purpose perfectly.
    // Pinned topics all have canonical names, and we have already ascertained that the name is unique,
    // meaning that another pinned topic is not occupying the same subject-ID. However, if the user made the mistake
    // of pinning the topic in the automatically managed subject-ID range, a conflict may still occur, in which case
    // we will apply the normal allocation logic and unpin the topic to avoid conflict.
    if (ok) {
        topic->subject_id = (uint16_t)(pinned ? topic->hash : (topic->hash % CY_TOPIC_SUBJECT_COUNT));
        while (&topic->index_subject_id != cavlSearch(&cy->topics_by_subject_id, // until inserted
                                                      topic,
                                                      &cavl_predicate_topic_subject_id,
                                                      &cavl_factory_topic_subject_id)) {
            topic->subject_id = (topic->subject_id + 1U) % CY_TOPIC_SUBJECT_COUNT;
        }
        assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    }

    // Insert into gossip time index tree; this is a non-unique index.
    if (ok) {
        (void)cavlSearch(
          &cy->topics_by_gossip_time, topic, &cavl_predicate_topic_gossip_time, &cavl_factory_topic_gossip_time);
    }

    if (ok) {
        cy->topic_count++;
        CY_TRACE(cy,
                 "New topic '%s'@%u [%zu total], hash %016llX, pinned %d, last gossip at %llu us",
                 topic->name,
                 topic->subject_id,
                 cy->topic_count,
                 (unsigned long long)topic->hash,
                 pinned,
                 (unsigned long long)topic->last_gossip_us);
    }
    return ok;
}

void cy_topic_destroy(struct cy_topic_t* const topic)
{
    assert(topic != NULL);
    // TODO IMPLEMENT
}

struct cy_topic_t* cy_topic_find_by_name(struct cy_t* const cy, const char* const name)
{
    assert(cy != NULL);
    assert(name != NULL);
    uint64_t                 hash = topic_hash(name, NULL);
    struct cy_topic_t* const topic =
      (struct cy_topic_t*)cavlSearch(&cy->topics_by_hash, &hash, &cavl_predicate_topic_hash_raw, NULL);
    if (topic == NULL) {
        return NULL;
    }
    assert(topic->hash == hash);
    assert(topic->cy == cy);
    return topic;
}

struct cy_topic_t* cy_topic_find_by_subject_id(struct cy_t* const cy, uint16_t subject_id)
{
    assert(cy != NULL);
    struct cy_tree_t* const t =
      cavlSearch(&cy->topics_by_subject_id, &subject_id, &cavl_predicate_topic_subject_id_raw, NULL);
    if (t == NULL) {
        return NULL;
    }
    struct cy_topic_t* topic = (struct cy_topic_t*)(((char*)t) - offsetof(struct cy_topic_t, index_subject_id));
    assert(topic->subject_id == subject_id);
    assert(topic->cy == cy);
    return topic;
}

static void topic_for_each_impl(struct cy_tree_t* const tree, // NOLINT(*-no-recursion)
                                void (*callback)(struct cy_topic_t* const topic, void* user),
                                void* const user)
{
    if (tree != NULL) {
        topic_for_each_impl(tree->lr[0], callback, user);
        callback((struct cy_topic_t*)tree, user);
        topic_for_each_impl(tree->lr[1], callback, user);
    }
}

void cy_topic_for_each(struct cy_t* const cy,
                       void (*callback)(struct cy_topic_t* const topic, void* user),
                       void* const user)
{
    if ((cy != NULL) && (callback != NULL)) {
        topic_for_each_impl(cy->topics_by_hash, callback, user);
    }
}

cy_err_t cy_subscribe(struct cy_topic_t* const         topic,
                      struct cy_subscription_t* const  sub,
                      const size_t                     extent,
                      const uint64_t                   transfer_id_timeout_us,
                      const cy_subscription_callback_t callback)
{
    assert(topic != NULL);
    assert(sub != NULL);
    assert((topic->name_length > 0) && (topic->name[0] != '\0'));
    assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    topic->sub_transfer_id_timeout_us = transfer_id_timeout_us;
    topic->sub_extent                 = extent;
    memset(sub, 0, sizeof(*sub));
    sub->next     = NULL;
    sub->topic    = topic;
    sub->callback = callback; // May be NULL, we don't check at this stage (we do check later, safety first).
    // Append the list.
    struct cy_subscription_t* last = topic->sub_list;
    while ((last != NULL) && (last->next != NULL)) {
        last = last->next;
    }
    if (last == NULL) {
        topic->sub_list = sub;
    } else {
        last->next = sub;
    }
    // Ensure the transport layer subscription is active.
    cy_err_t err = 0;
    if (!topic->sub_active) {
        err               = topic->cy->transport.subscribe(topic);
        topic->sub_active = err >= 0;
    }
    CY_TRACE(topic->cy,
             "New subscription to '%s'@%u, extent %zu; subscribe()->%d",
             topic->name,
             topic->subject_id,
             extent,
             err);
    return err;
}

cy_err_t cy_publish(struct cy_topic_t* const topic, const uint64_t tx_deadline_us, const struct cy_payload_t payload)
{
    assert(topic != NULL);
    assert((payload.data != NULL) || (payload.size == 0));
    assert((topic->name_length > 0) && (topic->name[0] != '\0'));
    assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    const cy_err_t res = topic->cy->transport.publish(topic, tx_deadline_us, payload);
    topic->pub_transfer_id++;
    return res;
}

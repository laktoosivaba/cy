/// Copyright (c) Pavel Kirienko <pavel@opencyphal.org>

#include "cy.h"
#include "_cy_cavl.h"

#include <assert.h>
#include <string.h>

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

static size_t popcount_all(const size_t nbits, const void* x)
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
// TODO FIXME REPLACE CRC64 WITH A BETTER 64-bit HASH FUNCTION

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
    const uint16_t x = cy_topic_get_subject_id(inner);
    if (outer == x) {
        return 0;
    }
    return (outer >= x) ? +1 : -1;
}

static int8_t cavl_predicate_topic_subject_id(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    uint16_t x = cy_topic_get_subject_id((struct cy_topic_t*)user_reference);
    return cavl_predicate_topic_subject_id_raw(&x, node);
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

// ReSharper disable CppDFAConstantParameter CppParameterMayBeConstPtrOrRef

/// A Bloom filter is a set-only structure so there is no way to clear a bit after it has been set.
/// It is only possible to purge the entire filter state.
static void bloom64_set(struct cy_bloom64_t* const bloom, const size_t value)
{
    assert(bloom != NULL);
    const size_t index = value % bloom->n_bits;
    bloom->storage[index / 64U] |= (1ULL << (index % 64U));
}

static bool bloom64_get(const struct cy_bloom64_t* const bloom, const size_t value)
{
    assert(bloom != NULL);
    const size_t index = value % bloom->n_bits;
    return (bloom->storage[index / 64U] & (1ULL << (index % 64U))) != 0;
}

static void bloom64_purge(struct cy_bloom64_t* const bloom)
{
    assert(bloom != NULL);
    for (size_t i = 0; i < (bloom->n_bits + 63U) / 64U; i++) { // dear compiler please unroll this
        bloom->storage[i] = 0U; // I suppose this is better than memset cuz we're aligned to 64 bits.
    }
}

/// This is guaranteed to return a valid node-ID. If the Bloom filter is not full, an unoccupied node-ID will be
/// chosen, and the corresponding entry in the filter will be set. If the filter is full, a random node-ID will be
/// chosen, which can only happen if more than filter capacity nodes are currently online.
/// The complexity is constant, independent of the filter occupancy.
///
/// In the future we could replace this with a deterministic algorithm that chooses the node-ID based on the UID
/// and a nonce. Perhaps it could be simply SplitMix64 seeded with the UID?
static uint16_t pick_node_id(struct cy_bloom64_t* const bloom, const uint16_t node_id_max)
{
    // The algorithm is hierarchical: find a 64-bit word that has at least one zero bit, then find a zero bit in it.
    // This somewhat undermines the randomness of the result, but it is always fast.
    const size_t num_words  = (smaller(node_id_max, bloom->n_bits) + 63U) / 64U;
    size_t       word_index = (size_t)random_uint(0U, num_words - 1U);
    for (size_t i = 0; i < num_words; i++) {
        if (bloom->storage[word_index] != UINT64_MAX) {
            break;
        }
        word_index = (word_index + 1U) % num_words;
    }
    const uint64_t word = bloom->storage[word_index];
    if (word == UINT64_MAX) {
        return (uint16_t)random_uint(0U, node_id_max); // The filter is full, fallback to random node-ID.
    }

    // Now we have a word with at least one zero bit. Find a random zero bit in it.
    uint8_t bit_index = (uint8_t)random_uint(0U, 63U);
    assert(word != UINT64_MAX);
    while ((word & (1ULL << bit_index)) != 0) { // guaranteed to terminate, see above.
        bit_index = (bit_index + 1U) % 64U;
    }

    // Now we have some valid free node-ID. Recall that the Bloom filter maps multiple values to the same bit.
    // This means that we can increase randomness by incrementing the node-ID by a multiple of the Bloom filter period.
    size_t node_id = (word_index * 64U) + bit_index;
    assert(node_id < node_id_max);
    assert(bloom64_get(bloom, node_id) == false);
    node_id += (size_t)random_uint(0, node_id_max / bloom->n_bits) * bloom->n_bits;
    assert(node_id < node_id_max);
    assert(bloom64_get(bloom, node_id) == false);
    bloom64_set(bloom, node_id);
    return (uint16_t)node_id;
}

// ReSharper restore CppDFAConstantParameter CppParameterMayBeConstPtrOrRef

// ----------------------------------------  TOPIC OPS  ----------------------------------------

static bool is_pinned(const uint64_t hash)
{
    return hash < CY_TOTAL_SUBJECT_COUNT;
}

/// log(N) index update requires removal and reinsertion.
static void update_last_gossip_time(struct cy_topic_t* const topic, const uint64_t ts_us)
{
    assert(topic->cy->topics_by_gossip_time != NULL); // This index is never empty if we have topics
    cavlRemove(&topic->cy->topics_by_gossip_time, &topic->index_gossip_time);
    topic->last_gossip_us              = ts_us;
    const struct cy_tree_t* const tree = cavlSearch(
      &topic->cy->topics_by_gossip_time, topic, cavl_predicate_topic_gossip_time, cavl_factory_topic_gossip_time);
    assert(tree == &topic->index_gossip_time);
}

static void schedule_gossip_asap(struct cy_topic_t* const topic)
{
    assert(topic->cy->topics_by_gossip_time != NULL); // This index is never empty if we have topics
    if (topic->last_gossip_us > 0) {                  // Don't do anything if it's already scheduled.
        CY_TRACE(
          topic->cy, "Rescheduling topic '%s'@%04x for gossip ASAP", topic->name, cy_topic_get_subject_id(topic));
        // This is an optional optimization: if this is a pinned topic, it normally cannot collide with another one
        // (unless the user placed it in the dynamically allocated subject-ID range, which is not our problem);
        // we are publishing it just to announce that we have it; as such, the urgency of this action is a bit lower
        // than that of an actual colliding topic announcement, so we choose next-greater time to deprioritize it.
        const uint64_t rank = is_pinned(topic->hash) ? 1 : 0;
        update_last_gossip_time(topic, rank);
    }
}

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

/// The topic hash is the key component of the protocol.
/// For pinned topics, hash<CY_TOTAL_SUBJECT_COUNT.
/// The probability of a random hash falling into the pinned range is ~4.44e-16, or about one in two quadrillion.
static uint64_t topic_hash(const char* const name)
{
    uint64_t hash = parse_pinned(name);
    if (hash >= CY_TOTAL_SUBJECT_COUNT) {
        hash = crc64we_string(name);
    }
    return hash;
}

static uint16_t topic_get_subject_id(const uint64_t hash, const uint64_t lamport_clock)
{
    if (is_pinned(hash)) {
        return (uint16_t)hash; // Pinned topics may exceed CY_TOPIC_SUBJECT_COUNT.
    }
    return (uint16_t)((hash + lamport_clock) % CY_TOPIC_SUBJECT_COUNT);
}

/// Increments the subject-ID of the topic until a free slot is found, which is then taken.
/// Remember that we have a hard guarantee that there are not more local topics than available subject-IDs,
/// meaning that this function is infallible.
///
/// Consider: every time a topic collides with another one, one of them has to move. The more collisions a topic has
/// seen, the further away it is from its preferred subject-ID. A topic never moves back (under modular arithmetic).
/// Meaning that whatever value of a subject-ID we receive from the network, if it's greater (modulo wise) than what
/// we have, it means that there was a collision and we have to follow suit. The incrementing stops until no more
/// collisions occur, or when we displace another topic by winning arbitration.
///
/// The new lamport clock cannot be zero if we're reallocating the topic. The only case when it's zero is when the
/// topic is locally created for the first time. In this case, there is no need to remove it from the subject index.
///
/// This function will schedule all affected topics for gossip, including the one that is being moved.
/// Sometimes this is undesirable; in that case the caller can restore the next gossip time after the call.
///
/// The complexity is O(N log(N)) where N is the number of local topics. This is because we have to search the AVL
/// index tree on every iteration, and there may be as many iterations as there are local topics in the theoretical
/// worst case. The amortized worst case is only O(log(N)) because the topics are sparsely distributed thanks to the
/// topic hash function, unless there is a large number of topics (~>1000).
static void allocate_topic(struct cy_topic_t* const topic, const uint64_t greater_lamport)
{
    struct cy_t* const cy = topic->cy;
    assert(cy->topic_count <= CY_TOPIC_SUBJECT_COUNT); // There is certain to be a free subject-ID!

    static const int         call_depth_indent = 2;
    static _Thread_local int call_depth        = 0U;
    call_depth++;
    CY_TRACE(cy,
             "%*sAllocating '%s' hash %016llx subject %04x lamport %llu->%llu subscribed %d...",
             (call_depth - 1) * call_depth_indent,
             "",
             topic->name,
             (unsigned long long)topic->hash,
             cy_topic_get_subject_id(topic),
             (unsigned long long)topic->lamport_clock,
             (unsigned long long)greater_lamport,
             (int)topic->subscribed);

    // We need to make sure no underlying resources are sitting on this topic before we move it.
    // Otherwise, changing the subject-ID field on the go may break something underneath.
    if (topic->subscribed) {
        cy->transport.unsubscribe(topic);
        topic->subscribed = false;
    }

    // We're not allowed to alter the Lamport clock as long as the topic remains in the tree! So we remove it first.
    if (greater_lamport > 0) { // If zero, the topic is not yet in the tree.
        cavlRemove(&cy->topics_by_subject_id, &topic->index_subject_id);
    }

    // Whenever we alter a topic, we need to make sure that everyone knows about it.
    // Recursively we can alter a lot of topics like this.
    schedule_gossip_asap(topic);

    // Find a free slot. Every time we find an occupied slot, we have to arbitrate against its current tenant.
    topic->lamport_clock = greater_lamport;
    size_t iter_count    = 0;
    while (true) {
        iter_count++;
        struct cy_tree_t* const t = cavlSearch(&cy->topics_by_subject_id, //
                                               topic,
                                               &cavl_predicate_topic_subject_id,
                                               &cavl_factory_topic_subject_id);
        assert(t != NULL); // we will create it if not found, meaning allocation succeeded
        if (t == &topic->index_subject_id) {
            break; // Done!
        }
        // Someone else is sitting on that subject-ID. We need to arbitrate.
        struct cy_topic_t* const other = (struct cy_topic_t*)((char*)t - offsetof(struct cy_topic_t, index_subject_id));
        assert(topic->hash != other->hash); // This would mean that we inserted the same topic twice, impossible
        if (topic->hash > other->hash) {
            topic->lamport_clock++; // We lost arbitration, keep looking.
        } else {
            // This is our slot now! The other topic has to move.
            // This can trigger a chain reaction that in the worst case can leave no topic unturned.
            // One issue is that the worst-case recursive call depth equals the number of topics in the system.
            allocate_topic(other, other->lamport_clock + 1U);
            // Remember that we're still out of tree at the moment. We pushed the other topic out of its slot,
            // but it is possible that there was a chain reaction that caused someone else to occupy this slot.
            // Since that someone else was ultimately pushed out by the topic that just lost arbitration to us,
            // we know that the new squatter will lose arbitration to us again.
            // We will handle it in the exact same way on the next iteration, so we just continue with the loop.
            // Now, moving that one could also cause a chain reaction, but we know that eventually we will run
            // out of low-rank topics to move and will succeed.
        }
    }

    // If a subscription is needed, restore it. Notice that if this call failed in the past, we will retry here
    // as long as there is at least one live subscriber.
    if (topic->sub_list != NULL) {
        const cy_err_t res = cy->transport.subscribe(topic);
        topic->subscribed  = res >= 0;
        if (!topic->subscribed) {
            cy->transport.handle_resubscription_err(topic, res); // ok not our problem anymore.
        }
    }

    CY_TRACE(cy,
             "%*s...allocated '%s' subject %04x lamport %llu subscribed %d iterations %zu",
             (call_depth - 1) * call_depth_indent,
             "",
             topic->name,
             cy_topic_get_subject_id(topic),
             (unsigned long long)topic->lamport_clock,
             (int)topic->subscribed,
             iter_count);
    assert(call_depth > 0);
    call_depth--;
}

// ----------------------------------------  HEARTBEAT IO  ----------------------------------------

struct topic_gossip_t
{
    uint64_t value;
    uint64_t hash;
    uint8_t  name_length;
    char     name[CY_TOPIC_NAME_MAX];
};
static_assert(sizeof(struct topic_gossip_t) == 8 + 4 + 2 + 2 + 1 + CY_TOPIC_NAME_MAX, "bad layout");

/// We could have used Nunavut, but we only need a single message and it's very simple, so we do it manually.
struct heartbeat_t
{
    uint32_t              uptime;
    uint16_t              _padding_a;
    uint16_t              user_word;
    uint64_t              uid;
    struct topic_gossip_t topic_gossip;
};
static_assert(sizeof(struct heartbeat_t) == 128, "bad layout");

static struct heartbeat_t make_heartbeat(const uint64_t    uptime_us,
                                         const uint64_t    uid,
                                         const uint64_t    value,
                                         const uint64_t    hash,
                                         const size_t      name_len,
                                         const char* const name)
{
    assert(name_len <= CY_TOPIC_NAME_MAX);
    struct heartbeat_t obj = {
        .uptime       = (uint32_t)(uptime_us / 1000000U),
        .uid          = uid,
        .topic_gossip = { .hash = hash, .value = value, .name_length = (uint8_t)name_len },
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

static cy_err_t publish_heartbeat(struct cy_topic_t* const topic, const uint64_t now)
{
    assert(topic != NULL);
    const struct cy_t* const cy = topic->cy;

    // Construct the heartbeat message.
    // TODO: communicate how the topic is used: in/out, some other metadata?
    const struct heartbeat_t msg = make_heartbeat(now - cy->started_at_us, //
                                                  cy->uid,
                                                  topic->lamport_clock,
                                                  topic->hash,
                                                  topic->name_length,
                                                  topic->name);
    const size_t             msz = get_heartbeat_size(&msg);
    assert(msz <= sizeof(msg));
    assert(msg.topic_gossip.name_length <= CY_TOPIC_NAME_MAX);
    const struct cy_payload_t payload = { .data = &msg, .size = msz }; // FIXME serialization

    // Publish the message.
    assert(cy->node_id <= cy->node_id_max);
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

    // Deserialize the message. TODO: deserialize properly.
    struct heartbeat_t heartbeat = { 0 };
    memcpy(&heartbeat, payload.data, smaller(payload.size, sizeof(heartbeat)));
    const struct topic_gossip_t* const other = &heartbeat.topic_gossip;
    // Even though we may not always deserialize the full name, we do always deserialize the name length field.
    if ((other->name_length == 0) || (other->name[0] != '/')) {
        return; // Not a topic.
    }

    // Find the topic in our local database.
    struct cy_t* const cy   = sub->topic->cy;
    struct cy_topic_t* mine = cy_topic_find_by_hash(cy, other->hash);
    if (mine == NULL) { // We don't know this topic, but we still need to check for a subject-ID collision.
        mine = cy_topic_find_by_subject_id(cy, topic_get_subject_id(other->hash, other->value));
        if (mine == NULL) {
            return; // We are not using this subject-ID, no collision.
        }
        assert(cy_topic_get_subject_id(mine) == topic_get_subject_id(other->hash, other->value));
        CY_TRACE(cy,
                 "Collision on subject %04x discovered via gossip from %016llx %04x; we %s:\n"
                 "\t local  topic hash=%016llx name='%s'\n"
                 "\t remote topic hash=%016llx name='%s'",
                 cy_topic_get_subject_id(mine),
                 (unsigned long long)heartbeat.uid,
                 transfer.remote_node_id,
                 ((mine->hash < other->hash) ? "WIN" : "LOSE"),
                 (unsigned long long)mine->hash,
                 mine->name,
                 (unsigned long long)other->hash,
                 other->name);
        // We have a subject-ID collision. Decide which one has to move. Currently, we apply a simple rule that can
        // be applied consistently by each node independently: lower hash wins. This way, pinned topics remain pinned
        // forever! If there is a conflict pinned vs. allocated, the pinned topic always wins!
        //
        // We don't need to do anything if we won, but we need to announce to the network (in particular to the
        // infringing node) that we are using this subject-ID, so that the loser knows that it has to move.
        //
        // If we lost, we need to gossip this topic ASAP as well because every other participant on this topic
        // will also move, but the trick is that the others could have settled on different subject-IDs.
        // Everyone needs to publish their own new allocation and then we will pick max subject-ID out of that.
        if (mine->hash >= other->hash) {
            // This will NEVER happen for pinned topics! Because:
            // 1. their names are canonical, so a name clash is not possible.
            // 2. their hash is just the pinned ID, which is guaranteed to be less than any real hash.
            assert(!is_pinned(mine->hash) && !is_pinned(other->hash));
            allocate_topic(mine, mine->lamport_clock + 1U);
        } else {
            schedule_gossip_asap(mine);
        }
    } else { // We have this topic! Check if we have consensus on the subject-ID.
        // Subject-IDs only modulo-grow on collisions. Given two values, we know that the smaller one is
        // non-viable because someone had to increment it, so there was a collision.
        assert(mine->hash == other->hash);
        if (mine->lamport_clock < other->value) {
            // Ours is older than the one in the message, meaning that we have to catch up.
            // But it could be that the subject-ID allocated by the other node does not suit us because we have a local
            // topic there already. In that case, we will simply keep bumping it until a free slot is found.
            // Since that free slot will be higher than what we just received, we become the winner in this transaction,
            // so we keep the new (higher) ID and gossip ASAP to let the other node catch up.
            CY_TRACE(cy,
                     "Topic '%s' hash %016llx Lamport rewind %llu -> %llu to restore consensus",
                     mine->name,
                     (unsigned long long)mine->hash,
                     (unsigned long long)mine->lamport_clock,
                     (unsigned long long)other->value);
            const uint64_t old_last_gossip_us = mine->last_gossip_us;
            allocate_topic(mine, other->value);
            if (mine->lamport_clock == other->value) {
                // We caught up exactly, we are in consensus, so there is no point gossipping this topic for now.
                update_last_gossip_time(mine, old_last_gossip_us);
            }
        } else if (mine->lamport_clock > other->value) {
            // Our subject-ID is greater than the one in the message, meaning that we survived more collisions,
            // so the other has to catch up.
            schedule_gossip_asap(mine);
        } else {
            (void)0; // we are in sync, nothing to do
        }
    }
}

// ----------------------------------------  PUBLIC API  ----------------------------------------

cy_err_t cy_new(struct cy_t* const             cy,
                const uint64_t                 uid,
                const uint16_t                 node_id,
                const uint16_t                 node_id_max,
                const size_t                   node_id_occupancy_bloom_filter_64bit_word_count,
                uint64_t* const                node_id_occupancy_bloom_filter_storage,
                const char* const              namespace_,
                struct cy_topic_t* const       heartbeat_topic,
                const cy_now_t                 now,
                const struct cy_transport_io_t transport_io)
{
    assert(cy != NULL);
    assert(uid != 0);
    assert((node_id_occupancy_bloom_filter_storage != NULL) && (node_id_occupancy_bloom_filter_64bit_word_count > 0));

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

    cy->node_id_bloom.n_bits  = node_id_occupancy_bloom_filter_64bit_word_count * 64U;
    cy->node_id_bloom.storage = node_id_occupancy_bloom_filter_storage;
    bloom64_purge(&cy->node_id_bloom);

    // If a node-ID is given explicitly, we want to publish our heartbeat ASAP to speed up network convergence
    // and to claim the address; if it's already taken, we will want to cause a collision to move the other node,
    // because manually assigned addresses take precedence over auto-assigned ones.
    // If we are not given a node-ID, we need to first listen to the network.
    cy->heartbeat_period_us = CY_HEARTBEAT_PERIOD_DEFAULT_us;
    cy->heartbeat_next_us   = cy->started_at_us;
    cy_err_t res            = 0;
    if (cy->node_id > cy->node_id_max) {
        cy->heartbeat_next_us += random_uint(CY_START_DELAY_MIN_us, CY_START_DELAY_MAX_us);
    } else {
        bloom64_set(&cy->node_id_bloom, cy->node_id);
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

    CY_TRACE(cy, "cy_new(%p)->%d", (void*)cy, res);
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
    if ((cy->node_id > cy->node_id_max) && !bloom64_get(&cy->node_id_bloom, metadata.remote_node_id)) {
        // The mean extra time is chosen to be simply two heartbeat periods.
        cy->heartbeat_next_us += random_uint(1, 3 * CY_HEARTBEAT_PERIOD_DEFAULT_us);
        CY_TRACE(cy,
                 "Discovered neighbor %u publishing on '%s'@%u; new Bloom popcount %zu",
                 metadata.remote_node_id,
                 topic->name,
                 cy_topic_get_subject_id(topic),
                 popcount_all(cy->node_id_bloom.n_bits, cy->node_id_bloom.storage) + 1U);
    }
    bloom64_set(&cy->node_id_bloom, metadata.remote_node_id);

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
        cy->node_id = pick_node_id(&cy->node_id_bloom, cy->node_id_max);
        assert(cy->node_id <= cy->node_id_max);
        res = cy->transport.set_node_id(cy);
        CY_TRACE(cy,
                 "Picked own node-ID %u; Bloom popcount %zu; set_node_id()->%d",
                 cy->node_id,
                 popcount_all(cy->node_id_bloom.n_bits, cy->node_id_bloom.storage),
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
        CY_TRACE(topic->cy, "Discriminator collision on '%s'@%u", topic->name, cy_topic_get_subject_id(topic));
        // Topics with the same time will be ordered FIFO -- the tree is stable.
        schedule_gossip_asap(topic);
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
             "Node-ID collision on %u; Bloom purge with popcount %zu",
             cy->node_id,
             popcount_all(cy->node_id_bloom.n_bits, cy->node_id_bloom.storage));
    // We must reset the Bloom filter because there may be tombstones in it.
    // It will be repopulated afresh during the delay we set below.
    bloom64_purge(&cy->node_id_bloom);
    // We don't want to reuse the same node-ID to avoid the risk of picking up RPC transfers addressed to the
    // conflicting node, so we mark it used. The conflicting node may continue using that address if it hasn't heard
    // us yet, which is preferable as it minimizes disruptions. If the other node heard us, it will also be abandoning
    // this address, but we don't want it either because there may be in-flight RPC transfers addressed to it.
    bloom64_set(&cy->node_id_bloom, cy->node_id);
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
    topic->hash                    = topic_hash(name);
    topic->lamport_clock           = 0; // starting from the preferred subject-ID.

    topic->user            = NULL;
    topic->pub_transfer_id = 0;
    topic->pub_priority    = cy_prio_nominal;
    topic->sub_list        = NULL;
    topic->subscribed      = false;

    bool ok = (topic->name_length > 1) && (topic->name_length <= CY_TOPIC_NAME_MAX) && (topic->name[0] == '/') &&
              (cy->topic_count < CY_TOPIC_SUBJECT_COUNT);

    // Insert the new topic into the name index tree. If it's not unique, bail out.
    if (ok) {
        const struct cy_tree_t* const res_tree =
          cavlSearch(&cy->topics_by_hash, topic, &cavl_predicate_topic_hash, &cavl_factory_topic_hash);
        assert(res_tree != NULL);
        ok = res_tree == &topic->index_hash; // Reject if the name is already taken.
    }

    if (ok) {
        // Ensure the topic is in the gossip index. This is needed for allocation.
        topic->last_gossip_us = 0;
        (void)cavlSearch(
          &cy->topics_by_gossip_time, topic, &cavl_predicate_topic_gossip_time, &cavl_factory_topic_gossip_time);

        // Allocate a subject-ID for the topic and insert it into the subject index tree.
        // Pinned topics all have canonical names, and we have already ascertained that the name is unique,
        // meaning that another pinned topic is not occupying the same subject-ID.
        // Remember that topics arbitrate locally the same way they do externally, meaning that adding a new local topic
        // may displace another local one.
        allocate_topic(topic, 0);

        cy->topic_count++;
        CY_TRACE(cy,
                 "New topic '%s'@%u [%zu total], hash %016llx, last gossip %llu us",
                 topic->name,
                 cy_topic_get_subject_id(topic),
                 cy->topic_count,
                 (unsigned long long)topic->hash,
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
    return cy_topic_find_by_hash(cy, topic_hash(name));
}

struct cy_topic_t* cy_topic_find_by_hash(struct cy_t* const cy, uint64_t hash)
{
    assert(cy != NULL);
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
    assert(cy_topic_get_subject_id(topic) == subject_id);
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

uint16_t cy_topic_get_subject_id(const struct cy_topic_t* const topic)
{
    return topic_get_subject_id(topic->hash, topic->lamport_clock);
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
    topic->sub_transfer_id_timeout_us = transfer_id_timeout_us;
    topic->sub_extent                 = extent;
    memset(sub, 0, sizeof(*sub));
    sub->next     = NULL;
    sub->topic    = topic;
    sub->callback = callback; // May be NULL, we don't check at this stage (we do check later, safety first).

    // Ensure this subscription is not already in the list.
    bool exists = false;
    {
        const struct cy_subscription_t* s = topic->sub_list;
        while (s != NULL) {
            if (s == sub) {
                exists = true;
                break;
            }
            s = s->next;
        }
    }

    // Append the list only if new. If it's not new, perhaps the user is trying to recover from a failed resubscription.
    if (!exists) {
        struct cy_subscription_t* s = topic->sub_list;
        while ((s != NULL) && (s->next != NULL)) {
            s = s->next;
        }
        if (s == NULL) {
            topic->sub_list = sub;
        } else {
            s->next = sub;
        }
    }

    // Ensure the transport layer subscription is active.
    cy_err_t err = 0;
    if (!topic->subscribed) {
        err               = topic->cy->transport.subscribe(topic);
        topic->subscribed = err >= 0;
    }
    CY_TRACE(topic->cy,
             "New subscription to '%s'@%u, extent %zu; subscribe()->%d",
             topic->name,
             cy_topic_get_subject_id(topic),
             extent,
             err);
    return err;
}

cy_err_t cy_publish(struct cy_topic_t* const topic, const uint64_t tx_deadline_us, const struct cy_payload_t payload)
{
    assert(topic != NULL);
    assert((payload.data != NULL) || (payload.size == 0));
    assert((topic->name_length > 0) && (topic->name[0] != '\0'));
    const cy_err_t res = topic->cy->transport.publish(topic, tx_deadline_us, payload);
    topic->pub_transfer_id++;
    return res;
}

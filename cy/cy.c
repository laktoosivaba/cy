/// Copyright (c) Pavel Kirienko

#include "cy.h"
#include "_cy_cavl.h"
#include <assert.h>
#include <stddef.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>

#define BYTE_BITS 8U
#define BYTE_MAX 0xFFU

#define HEARTBEAT_TOPIC_NAME "/7509"
#define HEARTBEAT_EXTENT 200
#define HEARTBEAT_PUB_PERIOD_us CY_UPDATE_INTERVAL_MIN_us
#define HEARTBEAT_PUB_TIMEOUT_us 1000000UL

/// If a collision is found, do not gossip the topic if it was last seen less than this long ago.
#define GOSSIP_RATE_LIMIT_us 100000UL

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

static inline uint64_t crc64we_string(const char* str)
{
    assert(str != NULL);
    uint64_t crc = CRC64WE_INITIAL;
    while (*str != '\0')
    {
        crc = crc64we_table[((uint8_t) *str) ^ (crc >> 56U)] ^ (crc << 8U);
        ++str;
    }
    return crc;
}

// ----------------------------------------  AVL TREE UTILITIES  ----------------------------------------

// hash index tree

static int8_t cavl_predicate_topic_hash_raw(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const uint64_t                 outer = *(uint64_t*) user_reference;
    const struct cy_topic_t* const inner =
        (const struct cy_topic_t*) (((const char*) node) - offsetof(struct cy_topic_t, index_hash));
    if (outer == inner->hash)
    {
        return 0;
    }
    return (outer >= inner->hash) ? +1 : -1;
}

static int8_t cavl_predicate_topic_hash(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    return cavl_predicate_topic_hash_raw(&(((struct cy_topic_t*) user_reference)->hash), node);
}

static struct cy_tree_t* cavl_factory_topic_hash(void* const user_reference)
{
    return &((struct cy_topic_t*) user_reference)->index_hash;
}

// subject-ID index tree

static int8_t cavl_predicate_topic_subject_id_raw(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const uint16_t                 outer = *(uint16_t*) user_reference;
    const struct cy_topic_t* const inner =
        (const struct cy_topic_t*) (((const char*) node) - offsetof(struct cy_topic_t, index_subject_id));
    if (outer == inner->subject_id)
    {
        return 0;
    }
    return (outer >= inner->subject_id) ? +1 : -1;
}

static int8_t cavl_predicate_topic_subject_id(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    return cavl_predicate_topic_subject_id_raw(&(((struct cy_topic_t*) user_reference)->subject_id), node);
}

static struct cy_tree_t* cavl_factory_topic_subject_id(void* const user_reference)
{
    return &((struct cy_topic_t*) user_reference)->index_subject_id;
}

// gossip time index tree

/// Gossip times do not have to be unique, so this comparator never returns 0.
static int8_t cavl_predicate_topic_gossip_time(void* const user_reference, const struct cy_tree_t* const node)
{
    assert((user_reference != NULL) && (node != NULL));
    const struct cy_topic_t* const outer = (struct cy_topic_t*) user_reference;
    const struct cy_topic_t* const inner =
        (const struct cy_topic_t*) (((const char*) node) - offsetof(struct cy_topic_t, index_gossip_time));
    return (outer->last_gossip_us >= inner->last_gossip_us) ? +1 : -1;
}

static struct cy_tree_t* cavl_factory_topic_gossip_time(void* const user_reference)
{
    return &((struct cy_topic_t*) user_reference)->index_gossip_time;
}

// ----------------------------------------  HEARTBEAT IO  ----------------------------------------

static inline size_t smaller(const size_t a, const size_t b)
{
    return (a < b) ? a : b;
}

struct topic_gossip_t
{
    struct cy_crdt_meta_t crdt_meta;
    uint32_t              ttl_ms;
    uint16_t              value;
    uint16_t              _padding_a;
    uint32_t              _padding_b;
    uint8_t               name_length;
    char                  name[CY_TOPIC_NAME_MAX];
};

/// We could have used Nunavut, but we only need a single message and it's very simple, so we do it manually.
struct heartbeat_t
{
    uint32_t              uptime;
    uint32_t              _padding_a;
    uint64_t              uid;
    struct topic_gossip_t topic_gossip;
};

static struct heartbeat_t make_heartbeat(const uint64_t              uptime_us,
                                         const uint64_t              uid,
                                         const struct cy_crdt_meta_t crdt_meta,
                                         const uint32_t              crdt_value,
                                         const char* const           crdt_name)
{
    struct heartbeat_t obj = {
        .uptime = (uint32_t) (uptime_us / 1000U),
        .uid    = uid,
        .topic_gossip =
            {
                .crdt_meta   = crdt_meta,
                .ttl_ms      = 0U,
                .value       = crdt_value,
                .name_length = (uint8_t) smaller(strlen(crdt_name), CY_TOPIC_NAME_MAX),
            },
    };
    memcpy(obj.topic_gossip.name, crdt_name, obj.topic_gossip.name_length);
    return obj;
}

static size_t get_heartbeat_size(const struct heartbeat_t* const obj)
{
    assert(obj != NULL);
    assert(obj->topic_gossip.name_length <= CY_TOPIC_NAME_MAX);
    return sizeof(*obj) - (CY_TOPIC_NAME_MAX - obj->topic_gossip.name_length);
}

static cy_err_t gossip(struct cy_topic_t* const topic)
{
    assert(topic != NULL);
    struct cy_t* const cy = topic->cy;

    const uint64_t           now = cy->now(cy);
    const struct heartbeat_t msg =
        make_heartbeat(now - cy->started_at_us, cy->uid, topic->crdt_meta, topic->subject_id, topic->name);
    const size_t msg_size = get_heartbeat_size(&msg);
    assert(msg_size <= sizeof(msg));
    assert(msg.topic_gossip.name_length <= CY_TOPIC_NAME_MAX);

    // TODO: proper serialization; this only works on little-endian machines.
    const cy_err_t res = cy->transport_publish(&cy->heartbeat_topic,
                                               now + HEARTBEAT_PUB_TIMEOUT_us,
                                               (struct cy_payload_t) {.data = &msg, .size = msg_size});
    cy->heartbeat_topic.pub_tfer_id++;
    if (res >= 0)
    {
        cy->heartbeat_last_us = now;
    }

    // Update the gossip time index, even if the publication failed, to ensure we don't get stuck publishing
    // the same gossip if error reporting is broken.
    {
        cavlRemove(&cy->topics_by_gossip_time, &topic->index_gossip_time);
        topic->last_gossip_us              = now;
        const struct cy_tree_t* const tree = cavlSearch(&cy->topics_by_gossip_time,
                                                        topic,
                                                        cavl_predicate_topic_gossip_time,
                                                        cavl_factory_topic_gossip_time);
        assert(tree == &topic->index_gossip_time);
    }
    return res;
}

static void on_heartbeat(struct cy_sub_t* const        sub,
                         const uint64_t                ts_us,
                         const struct cy_tfer_meta_t   tfer,
                         const struct cy_payload_mut_t payload)
{
    assert(sub != NULL);
    assert(payload.data != NULL);
    assert(payload.size <= sizeof(struct heartbeat_t));
    assert(payload.size >= (sizeof(struct heartbeat_t) - CY_TOPIC_NAME_MAX));

    (void) sub;
    (void) ts_us;
    (void) tfer;
    (void) payload;
    assert(false);  // TODO IMPLEMENT
}

// ----------------------------------------  TOPIC HASH  ----------------------------------------

/// Returns CY_SUBJECT_ID_INVALID if the string is not a valid stationary subject-ID form.
/// Stationary topic names must have only canonical names to ensure that no two topic names map to the same subject-ID.
/// The only requirement to ensure this is that there must be no leading zeros in the number.
static uint16_t parse_stationary(const char* s)
{
    if ((s == NULL) || (*s != '/'))
    {
        return CY_SUBJECT_ID_INVALID;
    }
    s++;
    if (*s == '\0')
    {
        return CY_SUBJECT_ID_INVALID;
    }
    uint32_t out = 0U;
    while (*s != '\0')
    {
        if ((*s < '0') || (*s > '9'))
        {
            return CY_SUBJECT_ID_INVALID;
        }
        if ((*s == '0') && (out == 0U))
        {
            return CY_SUBJECT_ID_INVALID;  // Non-canonical name -- leading zero!
        }
        out = (out * 10U) + (*s - '0');
        s++;
        if (out >= CY_TOTAL_SUBJECT_COUNT)
        {
            return CY_SUBJECT_ID_INVALID;
        }
    }
    return (uint16_t) out;
}

/// Topic hash is the cornerstone of the protocol.
static uint64_t topic_hash(const char* const name, bool* const out_stationary)
{
    uint64_t   hash = parse_stationary(name);
    const bool stat = hash < CY_TOTAL_SUBJECT_COUNT;
    if (!stat)
    {
        hash = crc64we_string(name);
    }
    if (out_stationary != NULL)
    {
        *out_stationary = stat;
    }
    return hash;
}

// ----------------------------------------  PUBLIC API  ----------------------------------------

cy_err_t cy_new(struct cy_t* const               cy,
                const uint64_t                   uid,
                const char* const                namespace_,
                const cy_now_t                   now,
                const cy_transport_publish_t     publish,
                const cy_transport_subscribe_t   subscribe,
                const cy_transport_unsubscribe_t unsubscribe,
                void* const                      user,
                void* const                      heartbeat_topic_user)
{
    assert(cy != NULL);
    assert(uid != 0);
    assert(now != NULL);
    assert(publish != NULL);
    assert(subscribe != NULL);
    assert(unsubscribe != NULL);

    // Init the object.
    memset(cy, 0, sizeof(*cy));
    cy->uid = uid;

    cy->namespace_len = (namespace_ == NULL) ? 0 : smaller(strlen(namespace_), CY_NAMESPACE_NAME_MAX);
    if (cy->namespace_len > 0)
    {
        memcpy(cy->namespace_, namespace_, cy->namespace_len);
        cy->namespace_[CY_NAMESPACE_NAME_MAX] = '\0';
    }
    else
    {
        cy->namespace_len = 1;
        cy->namespace_[0] = '~';
        cy->namespace_[1] = '\0';
    }
    cy->user                  = user;
    cy->now                   = now;
    cy->transport_publish     = publish;
    cy->transport_subscribe   = subscribe;
    cy->transport_unsubscribe = unsubscribe;
    cy->topics_by_name        = NULL;
    cy->topics_by_subject_id  = NULL;
    cy->topic_count           = 0;

    // Postpone calling the functions until after the object is set up.
    cy->started_at_us = cy->now(cy);

    // Register the heartbeat topic and subscribe. This is a stationary topic so no network exchange will take place.
    const bool topic_ok = cy_topic_new(cy, &cy->heartbeat_topic, HEARTBEAT_TOPIC_NAME);
    assert(topic_ok);
    cy->heartbeat_topic.user = heartbeat_topic_user;

    const cy_err_t res = cy_subscribe(&cy->heartbeat_topic,
                                      &cy->heartbeat_sub,
                                      HEARTBEAT_EXTENT,
                                      CY_TFER_ID_TIMEOUT_DEFAULT_us,
                                      &on_heartbeat);
    if (res < 0)
    {
        cy_topic_destroy(&cy->heartbeat_topic);
    }
    return res;
}

cy_err_t cy_update(struct cy_t* const cy, struct cy_update_event_t* const evt)
{
    assert(cy != NULL);

    if (evt != NULL)
    {
        assert(evt->topic != NULL);
        assert(evt->topic->cy == cy);
        // The transport layer is responsible for comparing the topic discriminator.
        // If we got something here, the discriminator must be correct.
        struct cy_sub_t* sub = evt->topic->sub_list;
        while (sub != NULL)
        {
            assert(sub->topic == evt->topic);
            struct cy_sub_t* const next = sub->next;  // In case the callback deletes this subscription.
            if (sub->callback != NULL)
            {
                sub->callback(sub, evt->ts_us, evt->tfer, evt->payload);
            }
            sub = next;
        }
    }

    /// We could have transmitted a heartbeat in response to someone asking for an allocation,
    /// or our own proposal, or as a corrective entry if a conflict is found.
    /// If that happened, we don't want to transmit another heartbeat immediately to regulate the traffic.
    /// This is why we check for the time here at the end, after the incoming transfer is handled.
    cy_err_t res = 0;
    if ((cy->now(cy) - cy->heartbeat_last_us) >= HEARTBEAT_PUB_PERIOD_us)
    {
        const struct cy_tree_t* const tree = cavlFindExtremum(cy->topics_by_gossip_time, false);
        assert(tree != NULL);  // We always have at least the heartbeat topic.
        struct cy_topic_t* const gossip_topic =
            (struct cy_topic_t*) (((char*) tree) - offsetof(struct cy_topic_t, index_hash));
        assert(gossip_topic->cy == cy);
        res = gossip(gossip_topic);
    }

    return res;
}

cy_err_t cy_notify_discriminator_collision(struct cy_topic_t* topic)
{
    assert((topic != NULL) && (topic->cy != NULL));
    cy_err_t       res = 0;
    const uint64_t now = topic->cy->now(topic->cy);
    if ((now - topic->last_gossip_us) >= GOSSIP_RATE_LIMIT_us)
    {
        res = gossip(topic);
        assert(topic->last_gossip_us >= now);
    }
    return res;
}

bool cy_topic_new(struct cy_t* const       cy,  //
                  struct cy_topic_t* const topic,
                  const char* const        name)
{
    assert(cy != NULL);
    assert(topic != NULL);
    assert(name != NULL);
    memset(topic, 0, sizeof(*topic));
    topic->cy = cy;

    // TODO: prefix the namespace unless the topic name starts with "/".
    // TODO: expand ~ to "/vvvv/pppp/iiiiiiii/"
    // TODO: canonicalize the topic name (repeated/trailing slash, strip whitespace, etc.).
    topic->name_len = strlen(name);
    memcpy(topic->name, name, smaller(topic->name_len, CY_TOPIC_NAME_MAX));
    topic->name[CY_TOPIC_NAME_MAX] = '\0';
    topic->hash                    = topic_hash(name, &topic->stationary);

    topic->crdt_meta.lamport_clock = 0;
    topic->crdt_meta.owner_uid     = 0;

    topic->user         = NULL;
    topic->pub_tfer_id  = 0;
    topic->pub_priority = cy_prio_nominal;
    topic->sub_list     = NULL;
    topic->sub_active   = false;

    bool ok = (topic->name_len > 0) && (topic->name_len <= CY_TOPIC_NAME_MAX) &&  //
              (cy->topic_count < CY_ALLOC_SUBJECT_COUNT);

    // Allocate a subject-ID for the topic.
    if (ok)
    {
        topic->subject_id = (uint16_t) (topic->hash % CY_ALLOC_SUBJECT_COUNT);
        while (cy_topic_find_by_subject_id(topic->cy, topic->subject_id) != NULL)
        {
            topic->subject_id = (topic->subject_id + 1U) % CY_ALLOC_SUBJECT_COUNT;
        }
        assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    }

    // Insert the new topic into the name index tree.
    if (ok)
    {
        const struct cy_tree_t* const res_tree = cavlSearch(&cy->topics_by_name,  //
                                                            topic,
                                                            &cavl_predicate_topic_hash,
                                                            &cavl_factory_topic_hash);
        assert(res_tree != NULL);
        const struct cy_topic_t* const res_topic =
            (const struct cy_topic_t*) (((const char*) res_tree) - offsetof(struct cy_topic_t, index_hash));
        ok = res_topic == topic;  // Reject if the name is already taken.
    }

    // Insert the new topic into the subject-ID index tree.
    if (ok)
    {
        const struct cy_tree_t* const res_tree = cavlSearch(&cy->topics_by_subject_id,  //
                                                            topic,
                                                            &cavl_predicate_topic_subject_id,
                                                            &cavl_factory_topic_subject_id);
        assert(res_tree != NULL);
        const struct cy_topic_t* const res_topic =
            (const struct cy_topic_t*) (((const char*) res_tree) - offsetof(struct cy_topic_t, index_subject_id));
        ok = res_topic == topic;  // Always true because we just ensured the uniqueness of the ID.
        assert(ok);
        // Since it's always true, no need to handle the failure case where we remove the topic from the name index.
    }

    // Notify the peers that we have a new topic, allowing anyone to object if a conflict is found.
    if (ok)
    {
        topic->crdt_meta.lamport_clock++;
        topic->crdt_meta.owner_uid = topic->cy->uid;
        (void) gossip(topic);
        assert(topic->last_gossip_us > 0);
    }

    cy->topic_count += ok ? 1 : 0;
    return ok;
}

struct cy_topic_t* cy_topic_find_by_name(struct cy_t* const cy, const char* const name)
{
    assert(cy != NULL);
    assert(name != NULL);
    uint64_t                hash = topic_hash(name, NULL);
    struct cy_tree_t* const t    = cavlSearch(&cy->topics_by_name, &hash, &cavl_predicate_topic_hash_raw, NULL);
    if (t == NULL)
    {
        return NULL;
    }
    struct cy_topic_t* topic = (struct cy_topic_t*) (((char*) t) - offsetof(struct cy_topic_t, index_hash));
    assert(topic->hash == hash);
    assert(topic->cy == cy);
    return topic;
}

struct cy_topic_t* cy_topic_find_by_subject_id(struct cy_t* const cy, uint16_t subject_id)
{
    assert(cy != NULL);
    struct cy_tree_t* const t =
        cavlSearch(&cy->topics_by_subject_id, &subject_id, &cavl_predicate_topic_subject_id_raw, NULL);
    if (t == NULL)
    {
        return NULL;
    }
    struct cy_topic_t* topic = (struct cy_topic_t*) (((char*) t) - offsetof(struct cy_topic_t, index_subject_id));
    assert(topic->subject_id == subject_id);
    assert(topic->cy == cy);
    return topic;
}

cy_err_t cy_subscribe(struct cy_topic_t* const topic,
                      struct cy_sub_t* const   sub,
                      const size_t             extent,
                      const uint64_t           tfer_id_timeout_us,
                      const cy_sub_callback_t  callback)
{
    assert(topic != NULL);
    assert(sub != NULL);
    assert((topic->name_len > 0) && (topic->name[0] != '\0'));
    assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    topic->sub_tfer_id_timeout_us = tfer_id_timeout_us;
    topic->sub_extent             = extent;
    memset(sub, 0, sizeof(*sub));
    sub->next     = NULL;
    sub->topic    = topic;
    sub->callback = callback;  // May be NULL, we don't check at this stage (we do check later, safety first).
    // Append the list.
    struct cy_sub_t* last = topic->sub_list;
    while ((last != NULL) && (last->next != NULL))
    {
        last = last->next;
    }
    if (last == NULL)
    {
        topic->sub_list = sub;
    }
    else
    {
        last->next = sub;
    }
    // Ensure the transport layer subscription is active.
    cy_err_t err = 0;
    if (!topic->sub_active)
    {
        err               = topic->cy->transport_subscribe(topic);
        topic->sub_active = err >= 0;
    }
    return err;
}

cy_err_t cy_publish(struct cy_topic_t* const topic, const uint64_t tx_deadline_us, const struct cy_payload_t payload)
{
    assert(topic != NULL);
    assert((payload.data != NULL) || (payload.size == 0));
    assert((topic->name_len > 0) && (topic->name[0] != '\0'));
    assert(topic->subject_id < CY_TOTAL_SUBJECT_COUNT);
    const cy_err_t res = topic->cy->transport_publish(topic, tx_deadline_us, payload);
    topic->pub_tfer_id++;  // The transfer-ID is always incremented, even if the message is not actually published.
    return res;
}

#include "cy_udp.h"
#include <time.h>
#include <stdio.h>
#include <ctype.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

static uint64_t random_uid(void)
{
    const uint16_t vid = UINT16_MAX; // This is the reserved public VID.
    const uint16_t pid = (uint16_t)rand();
    const uint32_t iid = (uint32_t)rand();
    return (((uint64_t)vid) << 48U) | (((uint64_t)pid) << 32U) | iid;
}

/// FNV1A 64-bit
static uint64_t arg_key_hash(const char* s)
{
    static const uint64_t prime = 1099511628211ULL;
    uint64_t              h     = 14695981039346656037ULL;
    for (unsigned char c; (c = (unsigned char)*s++);) {
        h ^= c;
        h *= prime;
    }
    return h;
}

struct arg_kv_t
{
    size_t      index;    ///< Argument index, where 0 is the program name.
    const char* key;      ///< NULL key indicates that no more arguments are available.
    uint64_t    key_hash; ///< arg_key_hash(key); 0 if no key.
    const char* value;    ///< NULL unless the argument matches "key=value". May be empty if "key=".
};

/// Returns the next argument key/value pair at every invocation. Returns NULL key when there are no more arguments.
/// Invokes exit(1) with a message if the arguments are malformed.
/// The argv array past the zeroth index may be mutated.
static struct arg_kv_t arg_kv_next(const int argc, char* argv[])
{
    if (argc <= 1) {
        fprintf(stderr,
                "Usage:\n\t%s key1[=value1] [key2[=value2] ...]\n"
                "No spaces around '=' are allowed.",
                argv[0]);
        exit(1);
    }
    static size_t   index = 1;
    struct arg_kv_t out   = { .index = index++, .key = NULL, .key_hash = 0, .value = NULL };
    if (((int)out.index) < argc) {
        out.key       = argv[out.index];
        char* const q = strchr(out.key, '=');
        if (q != NULL) {
            *q        = '\0';
            out.value = q + 1;
        }
        out.key_hash = arg_key_hash(out.key);
    }
    return out;
}

struct config_topic_t
{
    const char* name;
};

struct config_t
{
    uint32_t iface_address[CY_UDP_IFACE_COUNT_MAX];
    uint16_t local_node_id;
    uint64_t local_uid;
    size_t   tx_queue_capacity_per_iface;

    size_t                 topic_count;
    struct config_topic_t* topics;
};

struct config_t load_config(const int argc, char* argv[])
{
    // Load default config.
    struct config_t cfg = {
        .local_node_id               = CY_NODE_ID_INVALID,
        .local_uid                   = random_uid(),
        .tx_queue_capacity_per_iface = 1000,
        .topic_count                 = 0,
        .topics                      = calloc((size_t)(argc - 1), sizeof(struct config_topic_t)),
    };

    // Parse CLI args.
    size_t          iface_count = 0;
    struct arg_kv_t arg;
    while ((arg = arg_kv_next(argc, argv)).key_hash != 0) {
        if ((arg_key_hash("iface") == arg.key_hash) && (iface_count < CY_UDP_IFACE_COUNT_MAX)) {
            cfg.iface_address[iface_count++] = udp_parse_iface_address(arg.value);
        } else if (arg_key_hash("uid") == arg.key_hash) {
            cfg.local_uid = strtoull(arg.value, NULL, 0);
        } else if (arg_key_hash("node_id") == arg.key_hash) {
            cfg.local_node_id = (uint16_t)strtoul(arg.value, NULL, 0);
        } else if (arg_key_hash("tx_queue_capacity") == arg.key_hash) {
            cfg.tx_queue_capacity_per_iface = strtoul(arg.value, NULL, 0);
        } else if (arg.key[0] == '/') {
            cfg.topics[cfg.topic_count].name = arg.key;
            cfg.topic_count++;
        } else {
            fprintf(stderr, "Unexpected key #%zu: '%s'\n", arg.index, arg.key);
            exit(1);
        }
    }

    // Print the actual configs we're using.
    fprintf(stderr, "ifaces:");
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        fprintf(stderr, " 0x%08x", cfg.iface_address[i]);
    }
    fprintf(stderr, "\nid: 0x%016llx %04x\n", (unsigned long long)cfg.local_uid, cfg.local_node_id);
    fprintf(stderr, "tx_queue_capacity: %zu\n", cfg.tx_queue_capacity_per_iface);
    fprintf(stderr, "topics:");
    for (size_t i = 0; i < cfg.topic_count; i++) {
        fprintf(stderr, "\t%s", cfg.topics[i].name);
    }
    fprintf(stderr, "\n---\n");
    return cfg;
}

void tracing_subscription_callback(struct cy_subscription_t* subscription,
                                   uint64_t                  timestamp_us,
                                   struct cy_transfer_meta_t metadata,
                                   struct cy_payload_t       payload)
{
    // Convert payload to hex.
    char hex[payload.size * 2 + 1];
    for (size_t i = 0; i < payload.size; i++) {
        sprintf(hex + i * 2, "%02x", ((const uint8_t*)payload.data)[i]);
    }
    hex[sizeof(hex) - 1] = '\0';

    // Log the message.
    CY_TRACE(subscription->topic->cy,
             "\u2709 [sid=%04x nid=%04x tid=%08llx sz=%06zu ts=%09llu] @ %s: %s",
             subscription->topic->subject_id,
             metadata.remote_node_id,
             (unsigned long long)metadata.transfer_id,
             payload.size,
             (unsigned long long)timestamp_us,
             subscription->topic->name,
             hex);
}

int main(const int argc, char* argv[])
{
    srand((unsigned)time(NULL));
    const struct config_t cfg = load_config(argc, argv);

    // Set up the node instance.
    struct cy_udp_t cy_udp;
    {
        const cy_err_t res = cy_udp_new(&cy_udp, //
                                        cfg.local_uid,
                                        NULL,
                                        cfg.iface_address,
                                        cfg.local_node_id,
                                        cfg.tx_queue_capacity_per_iface);
        if (res < 0) {
            fprintf(stderr, "cy_udp_new: %d\n", res);
            return 1;
        }
    }

    // Create topics.
    struct cy_udp_topic_t*    topics = calloc(cfg.topic_count, sizeof(struct cy_udp_topic_t));
    struct cy_subscription_t* subs   = calloc(cfg.topic_count, sizeof(struct cy_subscription_t));
    for (size_t i = 0; i < cfg.topic_count; i++) {
        cy_err_t res = cy_udp_topic_new(&cy_udp, &topics[i], cfg.topics[i].name);
        if (res < 0) {
            fprintf(stderr, "cy_udp_topic_new: %d\n", res);
            return 1;
        }
        // Subscribe to the topic.
        res = cy_udp_subscribe(&topics[i], //
                               &subs[i],
                               1024 * 1024,
                               CY_TRANSFER_ID_TIMEOUT_DEFAULT_us,
                               tracing_subscription_callback);
        if (res < 0) {
            fprintf(stderr, "cy_udp_subscribe: %d\n", res);
            return 1;
        }
    }

    // Spin the event loop and publish on the topics.
    while (true) {
        const cy_err_t err_spin = cy_udp_spin_once(&cy_udp);
        if (err_spin < 0) {
            fprintf(stderr, "cy_udp_spin_once: %d\n", err_spin);
            break;
        }

        // TODO: topic publication
    }

    return 0;
}

void cy_trace(struct cy_t* const  cy,
              const char* const   file,
              const uint_fast16_t line,
              const char* const   func,
              const char* const   format,
              ...)
{
    // Capture the uptime timestamp ASAP.
    const uint64_t uptime_us = cy->now(cy) - cy->started_at_us;

    // Get the current wall time and format it.
    struct timespec ts;
    (void)timespec_get(&ts, TIME_UTC);
    const struct tm tm_local  = *localtime(&ts.tv_sec);
    char            hhmmss[9] = { 0 };
    (void)strftime(hhmmss, sizeof(hhmmss), "%H:%M:%S", &tm_local);

    // Print the header.
    const char* file_name = strrchr(file, '/');
    if (file_name != NULL) {
        file_name++;
    } else if ((file_name = strrchr(file, '\\')) != NULL) {
        file_name++;
    } else {
        file_name = file;
    }
    static const uint64_t mega = 1000000U;
    fprintf(stderr,
            "CY(%08llx %04x %05llu.%06llu \"%s\") %s.%03llu %s:%03u: %s: ",
            (unsigned long long)cy->uid,
            (unsigned)cy->node_id,
            (unsigned long long)(uptime_us / mega),
            (unsigned long long)(uptime_us % mega),
            cy->namespace_,
            hhmmss,
            (unsigned long long)ts.tv_nsec / mega,
            file_name,
            (unsigned)line,
            func);

    // Print the message.
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    // Finalize.
    fputc('\n', stderr);
    fflush(stderr);
}

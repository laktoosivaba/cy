#include "cy_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <time.h>

static uint64_t random_uid(void)
{
    const uint16_t vid = UINT16_MAX; // This is the reserved public VID.
    const uint16_t pid = (uint16_t)rand();
    const uint32_t iid = (uint32_t)rand();
    return (((uint64_t)vid) << 48U) | (((uint64_t)pid) << 32U) | iid;
}

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
    const char* key;      ///< Empty key indicates that no more arguments are available.
    uint64_t    key_hash; ///< FNV1A 64-bit hash of the key. 0 if no key.
    const char* value;    ///< NULL unless the argument matches "key=value". May be empty if "key=".
};

/// Returns the next argument key/value pair at every invocation. Returns NULL key when there are no more arguments.
/// Invokes exit(1) with a message if the arguments are malformed.
static struct arg_kv_t arg_kv_next(const int argc, char* argv[])
{
    static size_t index = 1;
    if (argc <= 1) {
        fprintf(stderr,
                "Usage: %s key1[=value1] [key2[=value2] ...]\n"
                "No spaces around '=' are allowed.",
                argv[0]);
        exit(1);
    }
    struct arg_kv_t out = { .index = index++, .key = NULL, .key_hash = 0, .value = NULL };
    if (((int)out.index) < argc) {
        out.key       = argv[out.index];
        out.key_hash  = arg_key_hash(out.key);
        char* const q = strchr(out.key, '=');
        if (q != NULL) {
            out.value = q + 1;
            *q        = '\0';
        }
    }
    return out;
}

int main(const int argc, char* argv[])
{
    srand((unsigned)time(NULL));

    uint32_t iface_address[CY_UDP_IFACE_COUNT_MAX] = { 0 };
    {
        size_t          iface_count = 0;
        struct arg_kv_t arg;
        while ((arg = arg_kv_next(argc, argv)).key_hash != 0) {
            if ((arg_key_hash("iface") == arg.key_hash) && (iface_count < CY_UDP_IFACE_COUNT_MAX)) {
                iface_address[iface_count++] = udp_parse_iface_address(arg.value);
            } else {
                fprintf(stderr, "Unexpected key #%zu: '%s'\n", arg.index, arg.key);
                exit(1);
            }
        }
    }
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        printf("iface %zu: 0x%08x\n", i, iface_address[i]);
    }

    const uint64_t uid = random_uid();
    printf("uid: 0x%016lx\n", uid);

    const size_t tx_queue_capacity_per_iface = 1000;

    // Set up the node instance.
    struct cy_udp_t cy_udp;
    const cy_err_t  res = cy_udp_new(&cy_udp, uid, NULL, iface_address, tx_queue_capacity_per_iface);
    if (res < 0) {
        printf("cy_udp_new: %d\n", res);
        return 1;
    }

    // Spin the event loop.
    while (true) {
        const cy_err_t err_spin = cy_udp_spin_once(&cy_udp);
        if (err_spin < 0) {
            printf("cy_udp_spin_once: %d\n", err_spin);
            break;
        }
    }

    return 0;
}

void cy_trace(struct cy_t* const cy, const char* const file, const uint_fast16_t line, const char* const format, ...)
{
    // Capture the uptime timestamp early.
    const uint64_t uptime_us = cy->now(cy) - cy->started_at_us;

    // Get the current wall time and format it.
    struct timespec ts;
    (void)timespec_get(&ts, TIME_UTC);
    const struct tm tm_local  = *localtime(&ts.tv_sec);
    char            hhmmss[9] = { 0 };
    (void)strftime(hhmmss, sizeof(hhmmss), "%H:%M:%S", &tm_local);

    // Print the header.
    static const uint64_t mega = 1000000U;
    fprintf(stderr,
            "CY(uid=%08llx,ns='%s',upt=%04llu.%06llu) %s.%03llu %s:%03u: ",
            (unsigned long long)cy->uid,
            cy->namespace_,
            (unsigned long long)(uptime_us / mega),
            (unsigned long long)(uptime_us % mega),
            hhmmss,
            (unsigned long long)ts.tv_nsec / mega,
            file,
            (unsigned)line);

    // Print the message.
    va_list args;
    va_start(args, format);
    vfprintf(stderr, format, args);
    va_end(args);

    // Finalize.
    fputc('\n', stderr);
    fflush(stderr);
}

#include "cy_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <time.h>

static uint16_t random_u16(void)
{
    return (uint16_t)(((uint64_t)rand()) % (UINT16_MAX + 1));
}

static uint32_t random_u32(void)
{
    return (((uint32_t)random_u16()) << 16U) | random_u16();
}

static uint64_t random_uid(void)
{
    const uint16_t vid = UINT16_MAX; // This is the reserved public VID.
    const uint16_t pid = random_u16();
    const uint32_t iid = random_u32();
    return (((uint64_t)vid) << 48U) | (((uint64_t)pid) << 32U) | iid;
}

int main(const int argc, const char* const argv[])
{
    srand((unsigned)time(NULL));

    uint32_t local_iface_address[CY_UDP_IFACE_COUNT_MAX] = { 0 };
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        if (i >= ((size_t)argc - 1U)) {
            break;
        }
        local_iface_address[i] = udp_parse_iface_address(argv[i + 1]);
    }
    for (size_t i = 0; i < CY_UDP_IFACE_COUNT_MAX; i++) {
        printf("iface %zu: 0x%08x\n", i, local_iface_address[i]);
    }

    const uint64_t uid = random_uid();
    printf("uid: 0x%016lx\n", uid);

    const size_t tx_queue_capacity_per_iface = 1000;

    // Set up the node instance.
    struct cy_udp_t cy_udp;
    const cy_err_t  res = cy_udp_new(&cy_udp, uid, NULL, local_iface_address, tx_queue_capacity_per_iface);
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
    static const uint64_t mega      = 1000000U;
    const uint64_t        uptime_us = cy->now(cy) - cy->started_at_us;

    // Get the current wall time and format it.
    struct timespec ts;
    (void)timespec_get(&ts, TIME_UTC);
    const struct tm tm_local  = *localtime(&ts.tv_sec);
    char            hhmmss[9] = { 0 };
    (void)strftime(hhmmss, sizeof hhmmss, "%H:%M:%S", &tm_local);

    // Print the header.
    fprintf(stderr,
            "CY(%08llx,'%s',%04llu.%06llu) %s.%03llu %s:%03u: ",
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

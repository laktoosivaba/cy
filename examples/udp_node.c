#include "cy_udp.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
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
    const uint16_t vid = UINT16_MAX;
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

    struct cy_udp_t cy_udp;
    const cy_err_t  res = cy_udp_new(&cy_udp, uid, NULL, local_iface_address, tx_queue_capacity_per_iface);
    printf("cy_udp_new: %d\n", res);

    // TODO: print statistics at the end, including transfer-IDs of all topics.

    return 0;
}

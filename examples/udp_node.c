#include "udp.h"
#include <cy.h>
#include <stdlib.h>
#include <udpard.h>

#define IFACE_COUNT_MAX 3

typedef cy_err_t cyudp_err_t;

struct cyudp_topic_t
{
    struct cy_topic_t           base;
    struct UdpardRxSubscription udpard;
    void*                       user;
};

struct cyudp_t
{
    struct cy_t                    base;
    struct UdpardTx                tx[IFACE_COUNT_MAX];
    struct UdpardMemoryResource    mem;
    struct UdpardRxMemoryResources rx_mem;
    UDPTxHandle                    sock_tx[IFACE_COUNT_MAX];
    UDPRxHandle                    sock_rx[IFACE_COUNT_MAX];
    struct UdpardRxSubscription    heartbeat_subscription;
    void*                          user;
};

void* mem_alloc(void* const user, const size_t size)
{
    (void)user;
    return malloc(size);
}

void mem_free(void* const user, void* const ptr)
{
    (void)user;
    free(ptr);
}

#if 0
cyudp_err_t cyudp_new(struct cyudp_t* const cyudp, const uint64_t uid, const char* const namespace_, void* const user)
{
    cyudp_err_t res =
      cy_new(&cyudp->base, uid, namespace_, NULL, NULL, NULL, NULL, cyudp, &cyudp->heartbeat_subscription);
}
#endif

int main(void)
{
    return 0;
}

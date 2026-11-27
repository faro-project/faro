// The C the tunnel needs that Swift can't import directly: libresolv's
// resolver configuration (resolv.h's state struct and its functions are
// macros over res_9_* names that Swift doesn't see).

#include <resolv.h>
#include <string.h>
#include <sys/socket.h>

/// Copies the system's default resolver addresses (at most `max`, at most
/// 8) into `out` and returns how many there are. Before the tunnel's DNS
/// settings apply these are the network's own resolvers; afterwards the
/// system reports the tunnel's DNS address instead.
static inline int faro_system_resolvers(struct sockaddr_storage *out, int max) {
    struct __res_state state;
    memset(&state, 0, sizeof state);
    if (res_ninit(&state) != 0) {
        return 0;
    }
    union res_sockaddr_union servers[8];
    int n = res_getservers(&state, servers, max < 8 ? max : 8);
    for (int i = 0; i < n; i++) {
        memset(&out[i], 0, sizeof out[i]);
        memcpy(&out[i], &servers[i],
               sizeof servers[i] < sizeof out[i] ? sizeof servers[i] : sizeof out[i]);
    }
    res_ndestroy(&state);
    return n < 0 ? 0 : n;
}

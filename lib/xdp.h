#ifndef _ZEBRA_XDP_H
#define _ZEBRA_XDP_H

#include "prefix.h"

#ifdef __cplusplus
extern "C" {
#endif

extern void xdp_init(void);
extern void xdp_qppb_prefix_mark(const struct prefix *p, uint8_t dscp, bool add);
/* extern void xdp_map_dscp_to_vrf(uint8_t dscp, uint8_t vrf_id, bool add); */
extern void test_lpm_map(void);

#ifdef __cplusplus
}
#endif
#endif /* _ZEBRA_XDP_H */

/* DSCP manipulation routines
 *
 * Author: Volodymyr Huti <v.huti@vyos.io>
 *
 * Copyright (C) 2022 VyOS https://vyos.io
 *
 * This file is part of FRRouting (FRR).
 *
 * FRR is free software; you can redistribute it and/or modify it under the
 * terms of the GNU General Public License as published by the Free Software
 * Foundation; either version 2, or (at your option) any later version.
 *
 * FRR is distributed in the hope that it will be useful, but WITHOUT ANY
 * WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef FRR_DSCP_H
#define FRR_DSCP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <zebra.h>
#include "vty.h"

#define DSFIELD_DSCP (0xfc) /* Upper 6 bits of DS field: DSCP */
#define DSFIELD_ECN (0x03)  /* Lower 2 bits of DS field: BCN */

enum dscp_val {
	DSCP_CS0 = 0x00,
	DSCP_CS1 = 0x08,
	DSCP_CS2 = 0x10,
	DSCP_CS3 = 0x18,
	DSCP_CS4 = 0x20,
	DSCP_CS5 = 0x28,
	DSCP_CS6 = 0x30,
	DSCP_CS7 = 0x38,
	DSCP_AF11 = 0x0A,
	DSCP_AF12 = 0x0C,
	DSCP_AF13 = 0x0E,
	DSCP_AF21 = 0x12,
	DSCP_AF22 = 0x14,
	DSCP_AF23 = 0x16,
	DSCP_AF31 = 0x1A,
	DSCP_AF32 = 0x1C,
	DSCP_AF33 = 0x1E,
	DSCP_AF41 = 0x22,
	DSCP_AF42 = 0x34,
	DSCP_AF43 = 0x26,
	DSCP_EF = 0x2E,
	DSCP_VOICE = 0x2C,
	DSCP_MAX = DSCP_CS7 + 1,
	DSCP_ERR
};

extern uint8_t dscp_decode(const char *dscp, struct vty *vty);
extern uint8_t dscp_decode_enum(const char *dscp);
extern const char *dscp_enum_str(int dscp);

#ifdef __cplusplus
}
#endif

#endif /* FRR_DSCP_H */

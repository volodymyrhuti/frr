// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * DSCP manipulation routines
 * Copyright (C) 2023 VyOS Inc.
 * Volodymyr Huti
 */

#include "dscp.h"

static const struct {
	const char *name;
	int val;
} dscp_enum_int_map[] = {
	{"cs0", DSCP_CS0},	    {"cs1", DSCP_CS1},	 {"cs2", DSCP_CS2},
	{"cs3", DSCP_CS3},	    {"cs4", DSCP_CS4},	 {"cs5", DSCP_CS5},
	{"cs6", DSCP_CS6},	    {"cs7", DSCP_CS7},	 {"af11", DSCP_AF11},
	{"af12", DSCP_AF12},	    {"af13", DSCP_AF13}, {"af21", DSCP_AF21},
	{"af22", DSCP_AF22},	    {"af23", DSCP_AF23}, {"af31", DSCP_AF31},
	{"af32", DSCP_AF32},	    {"af33", DSCP_AF33}, {"af41", DSCP_AF41},
	{"af42", DSCP_AF42},	    {"af43", DSCP_AF43}, {"ef", DSCP_EF},
	{"voice-admit", DSCP_VOICE}};

static const char *dscp_int_enum_map[DSCP_MAX] = {
	[DSCP_CS0] = "cs0",	     [DSCP_CS1] = "cs1",   [DSCP_CS2] = "cs2",
	[DSCP_CS3] = "cs3",	     [DSCP_CS4] = "cs4",   [DSCP_CS5] = "cs5",
	[DSCP_CS6] = "cs6",	     [DSCP_CS7] = "cs7",   [DSCP_AF11] = "af11",
	[DSCP_AF12] = "af12",	     [DSCP_AF13] = "af13", [DSCP_AF21] = "af21",
	[DSCP_AF22] = "af22",	     [DSCP_AF23] = "af23", [DSCP_AF31] = "af31",
	[DSCP_AF32] = "af32",	     [DSCP_AF33] = "af33", [DSCP_AF41] = "af41",
	[DSCP_AF42] = "af42",	     [DSCP_AF43] = "af43", [DSCP_EF] = "ef",
	[DSCP_VOICE] = "voice-admit"};

static const int dscp_msize =
	(sizeof(dscp_enum_int_map) / sizeof(*dscp_enum_int_map));

/* Decodes a standardized DSCP into its representative value */
uint8_t dscp_decode_enum(const char *name)
{
	int dscp_val = -1;

	for (int i = 0; i < dscp_msize; ++i) {
		if (!strcmp(dscp_enum_int_map[i].name, name)) {
			dscp_val = dscp_enum_int_map[i].val;
			break;
		}
	}

	return dscp_val;
}

const char *dscp_enum_str(int dscp)
{
	return (dscp < DSCP_MAX) ? dscp_int_enum_map[dscp] : NULL;
}

uint8_t dscp_decode(const char *dscp, char *msg, int len)
{
	uint8_t rawDscp, tmpDscp;
	bool isANumber = true;
	char dscpname[100];

	for (int i = 0; i < (int)strlen(dscp); i++) {
		/* Letters are not numbers */
		if (!isdigit(dscp[i]))
			isANumber = false;

		/* Lowercase the dscp enum (if needed) */
		if (isupper(dscp[i]))
			dscpname[i] = tolower(dscp[i]);
		else
			dscpname[i] = dscp[i];
	}
	dscpname[strlen(dscp)] = '\0';

	if (isANumber) {
		/* dscp passed is a regular number */
		long dscpAsNum = strtol(dscp, NULL, 0);

		if (dscpAsNum > DSFIELD_DSCP >> 2) {
			snprintf(msg, len,
				"dscp (%s) must be less than 64", dscp);
			return DSCP_ERR;
		}
		rawDscp = dscpAsNum;
	} else {
		/* check dscp if it is an enum like cs0 */
		tmpDscp = dscp_decode_enum(dscpname);
		if (tmpDscp > DSFIELD_DSCP) {
			snprintf(msg, len, "Invalid dscp value: %s", dscpname);
			return DSCP_ERR;
		}
		rawDscp = tmpDscp;
	}

	return rawDscp;
}

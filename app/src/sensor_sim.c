/*
 * SPDX-License-Identifier: Apache-2.0
 */

#include "sensor_sim.h"

#define BASE_MDEGC      21000 /* 21.000 C */
#define AMPLITUDE_MDEGC 1500  /* +/- 1.500 C */
#define PERIOD          20    /* readings per full cycle */

int32_t sensor_sim_read_mdegc(uint32_t n)
{
	/* Triangle wave: integer only, no floating point or libm needed. */
	uint32_t phase = n % PERIOD;
	int32_t half = PERIOD / 2;
	int32_t pos = (phase < (uint32_t)half) ? (int32_t)phase : (int32_t)(PERIOD - phase);

	return BASE_MDEGC - AMPLITUDE_MDEGC + (2 * AMPLITUDE_MDEGC * pos) / half;
}

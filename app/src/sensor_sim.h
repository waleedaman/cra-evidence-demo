/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * Simulated temperature sensor. There is no real sensor in this demo; the
 * values follow a fixed, deterministic pattern so runs are comparable.
 */

#ifndef SENSOR_SIM_H_
#define SENSOR_SIM_H_

#include <stdint.h>

/* Returns the n-th simulated reading in milli-degrees Celsius. */
int32_t sensor_sim_read_mdegc(uint32_t n);

#endif /* SENSOR_SIM_H_ */

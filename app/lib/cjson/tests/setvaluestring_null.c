/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * CVE-2024-31755: cJSON_SetValuestring(object, NULL) dereferences NULL in cJSON 1.7.17.
 * Host test, built twice by scripts/cjson-patch-test.sh: against the upstream 1.7.17
 * cJSON.c (patch reversed) and against the patched copy the firmware uses.
 */
#include <stdio.h>
#include "cJSON.h"

int main(void)
{
	cJSON *s = cJSON_CreateString("x");
	char *r;

	printf("cJSON %s: cJSON_SetValuestring(obj, NULL) ... ", cJSON_Version());
	fflush(stdout);
	r = cJSON_SetValuestring(s, NULL);
	printf("returned %s\n", r == NULL ? "NULL (rejected)" : "a pointer");
	cJSON_Delete(s);
	return r == NULL ? 0 : 1;
}

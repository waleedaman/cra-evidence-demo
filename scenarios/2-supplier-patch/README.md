# Scenario 2: supplier patch, version unchanged

**Claim:** "we backported the fix" is invisible to scanners. The version stays 1.7.17,
every database keeps reporting the CVE, and only a decision with evidence plus a VEX
statement communicates the truth.

**Setup:** `app/lib/cjson/cJSON.c` = upstream v1.7.17 + upstream commit
7e4d5dabe7a9b754c601f214e65b544e67ba9f59 (`patches/0001-...patch`), the fix for
CVE-2024-31755 (NULL dereference in `cJSON_SetValuestring`).

| Step | Expected |
| --- | --- |
| finding | CVE-2024-31755, High, cjson 1.7.17, Grype (`= 1.7.17`) and OSV |
| patch | the one-line upstream fix |
| cjson-test | upstream 1.7.17: CRASH (signal 11); firmware copy: returns NULL |
| decision | status `fixed`; evidence: patch, upstream commit, test transcript, symbols |
| vex SIGN=1 | 37 statements, signed |
| vex-statement | `"status": "fixed"` for `pkg:github/davegamble/cjson@v1.7.17` in this firmware |

**Discussion point for Q&A:** `make evidence` also shows that `cJSON_SetValuestring` is
not linked into this firmware at all, so `not_affected / vulnerable_code_not_present`
would be true too. We record `fixed` because the fix is the stronger, lasting statement:
it stays true when the application starts calling the function.

**Alternative considered:** CVE-2023-53154 (`parse_string`, fixed upstream in 1.7.18);
its fix is a larger change and the firmware does not parse JSON.

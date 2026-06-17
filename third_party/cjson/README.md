# cJSON compatibility layer

This directory contains a tiny cJSON-compatible parser written for this repository.

It implements the subset needed by `netwatch-c`:

- objects
- arrays
- strings
- booleans
- null
- `cJSON_Parse`
- `cJSON_Delete`
- `cJSON_GetObjectItemCaseSensitive`
- `cJSON_GetArraySize`
- `cJSON_GetArrayItem`
- `cJSON_ArrayForEach`

It intentionally does not implement JSON numbers because `netwatch-c` config does not need them.

If you want the official cJSON implementation, replace `cJSON.c` and `cJSON.h` in this directory with official upstream files.

#ifndef NETWATCH_CJSON_H
#define NETWATCH_CJSON_H

#ifdef __cplusplus
extern "C" {
#endif

#define cJSON_False 1
#define cJSON_True 2
#define cJSON_NULL 4
#define cJSON_String 8
#define cJSON_Array 16
#define cJSON_Object 32

typedef struct cJSON {
  struct cJSON *next;
  struct cJSON *child;
  int type;
  char *valuestring;
  char *string;
} cJSON;

cJSON *cJSON_Parse(const char *text);
void cJSON_Delete(cJSON *item);
cJSON *cJSON_GetObjectItemCaseSensitive(const cJSON *object, const char *string);
int cJSON_GetArraySize(const cJSON *array);
cJSON *cJSON_GetArrayItem(const cJSON *array, int index);

#define cJSON_IsFalse(item) ((item) && (item)->type == cJSON_False)
#define cJSON_IsTrue(item) ((item) && (item)->type == cJSON_True)
#define cJSON_IsBool(item) ((item) && ((item)->type == cJSON_False || (item)->type == cJSON_True))
#define cJSON_IsNull(item) ((item) && (item)->type == cJSON_NULL)
#define cJSON_IsString(item) ((item) && (item)->type == cJSON_String && (item)->valuestring)
#define cJSON_IsArray(item) ((item) && (item)->type == cJSON_Array)
#define cJSON_IsObject(item) ((item) && (item)->type == cJSON_Object)
#define cJSON_ArrayForEach(element, array) \
  for ((element) = (array) ? (array)->child : 0; (element); (element) = (element)->next)

#ifdef __cplusplus
}
#endif

#endif

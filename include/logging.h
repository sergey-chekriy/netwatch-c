#ifndef NETWATCH_LOGGING_H
#define NETWATCH_LOGGING_H

#include <stddef.h>

char *default_log_path(void);
int log_message(const char *log_path, const char *msg, char *err, size_t err_len);

#endif

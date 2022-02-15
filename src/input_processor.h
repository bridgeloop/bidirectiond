#ifndef bidirectiond__fifo_processor__h
#define bidirectiond__fifo_processor__h

#include <stddef.h>
#include <sys/types.h>
#include <stdbool.h>

void input_processor(int fd, char *br_buf, int br_buf_sz);

#endif

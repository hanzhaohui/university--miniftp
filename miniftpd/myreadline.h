#ifndef MY_READLINE_H_H_
#define MY_READLINE_H_H_
#include "common.h"
#include "sysutil.h"

ssize_t my_readline(int fd, void * vptr, size_t maxlen);

#endif /* MY_READLINE_H_H_ */

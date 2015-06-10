#include "myreadline.h"

static int read_cnt;
static char * read_ptr;
static char read_buf[MAXLINE];

static ssize_t my_read(int fd, char * ptr)
{
	if (read_cnt <= 0)
	{
	again:
		if ((read_cnt = readn(fd, read_buf, sizeof(read_buf))) == -1)
		{
			if (errno == EINTR)
			{
				goto again;
			}
			return -1;
		}
		else if (read_cnt == 0)
		{
			return 0;
		}
		
		read_ptr = read_buf;
	}
	
	--read_cnt;
	*ptr = *read_ptr++;
	return 1;
}

ssize_t my_readline(int fd, void * vptr, size_t maxlen)
{
	ssize_t loopsize, rc;
	char c, *ptr;
	ptr = vptr;
	
	for (loopsize = 1; loopsize < maxlen; ++loopsize)
	{
		if ((rc = my_read(fd, &c)) == 1)
		{
			*ptr++ = c;
			if (c == '\n')
			{
				*ptr = '\0';
				return loopsize;
			}
		}
		else if (rc == 0)
		{
			break;
		}
		else 
		{
			return -1;
		}
	}
	*ptr = '\0';
	return loopsize - 1;
}
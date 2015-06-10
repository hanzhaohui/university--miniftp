#include "ftpproto.h"
#include "sysutil.h"
#include "str.h"
#include "ftpcodes.h"
#include "tunable.h"
#include "privsock.h"
#include "myreadline.h"

void ftp_reply(session_t *sess, int status, const char *text);
void ftp_lreply(session_t *sess, int status, const char *text);

int list_common(session_t *sess, int detail);

int get_transfer_fd(session_t *sess);
int port_active(session_t *sess);
int pasv_active(session_t *sess);

static void do_user(session_t *sess);
static void do_pass(session_t *sess);
static void do_cwd(session_t *sess);
static void do_cdup(session_t *sess);
static void do_quit(session_t *sess);
static void do_port(session_t *sess);
static void do_pasv(session_t *sess);
static void do_type(session_t *sess);
static void do_stru(session_t *sess);
static void do_mode(session_t *sess);
static void do_retr(session_t *sess);
static void do_stor(session_t *sess);
static void do_appe(session_t *sess);
static void do_list(session_t *sess);
// static void do_nlst(session_t *sess);
static void do_rest(session_t *sess);
static void do_abor(session_t *sess);
static void do_pwd(session_t *sess);
static void do_mkd(session_t *sess);
static void do_rmd(session_t *sess);
static void do_dele(session_t *sess);
static void do_rnfr(session_t *sess);
static void do_rnto(session_t *sess);
static void do_site(session_t *sess);
static void do_syst(session_t *sess);
static void do_feat(session_t *sess);
static void do_size(session_t *sess);
static void do_stat(session_t *sess);
static void do_noop(session_t *sess);
static void do_help(session_t *sess);

/* 一个命令对应一个命令处理函数 */
typedef struct ftpcmd
{
	const char *cmd;
	void (*cmd_handler)(session_t *sess);
} ftpcmd_t;


static ftpcmd_t ctrl_cmds[] = {
	/* 访问控制命令 */
	{"USER",	do_user	},
	{"PASS",	do_pass	},
	{"CWD",		do_cwd	},
	{"XCWD",	do_cwd	},
	{"CDUP",	do_cdup	},
	{"XCUP",	do_cdup	},
	{"QUIT",	do_quit	},
	{"ACCT",	NULL	},
	{"SMNT",	NULL	},
	{"REIN",	NULL	},
	/* 传输参数命令 */
	{"PORT",	do_port	},
	{"PASV",	do_pasv	},
	{"TYPE",	do_type	},
	{"STRU",	do_stru	},
	{"MODE",	do_mode	},

	/* 服务命令 */
	{"RETR",	do_retr	},
	{"STOR",	do_stor	},
	{"APPE",	do_appe	},
	{"LIST",	do_list	},
	{"NLST",	do_list	},
	{"REST",	do_rest	},
	{"ABOR",	do_abor	},
	{"\377\364\377\362ABOR", do_abor},
	{"PWD",		do_pwd	},
	{"XPWD",	do_pwd	},
	{"MKD",		do_mkd	},
	{"XMKD",	do_mkd	},
	{"RMD",		do_rmd	},
	{"XRMD",	do_rmd	},
	{"DELE",	do_dele	},
	{"RNFR",	do_rnfr	},
	{"RNTO",	do_rnto	},
	{"SITE",	do_site	},
	{"SYST",	do_syst	},
	{"FEAT",	do_feat },
	{"SIZE",	do_size	},
	{"STAT",	do_stat	},
	{"NOOP",	do_noop	},
	{"HELP",	do_help	},
	{"STOU",	NULL	},
	{"ALLO",	NULL	}
};



void handle_child(session_t *sess)
{
	ftp_reply(sess, FTP_GREET, "(miniftpd 0.1)");
	int ret;
	while (1)
	{
		memset(sess->cmdline, 0, sizeof(sess->cmdline));
		memset(sess->cmd, 0, sizeof(sess->cmd));
		memset(sess->arg, 0, sizeof(sess->arg));
		ret = readline(sess->ctrl_fd, sess->cmdline, MAX_COMMAND_LINE);
		if (ret == -1)
			ERR_EXIT("readline");
		else if (ret == 0)
			exit(EXIT_SUCCESS);

		printf("cmdline=[%s]\n", sess->cmdline);
		// 去除\r\n
		str_trim_crlf(sess->cmdline);
		printf("cmdline=[%s]\n", sess->cmdline);
		// 解析FTP命令与参数
		str_split(sess->cmdline, sess->cmd, sess->arg, ' ');
		printf("cmd=[%s] arg=[%s]\n", sess->cmd, sess->arg);
		// 将命令转换为大写
		str_upper(sess->cmd);
		// 处理FTP命令
		/*
		if (strcmp("USER", sess->cmd) == 0)
		{
			do_user(sess);
		}
		else if (strcmp("PASS", sess->cmd) == 0)
		{
			do_pass(sess);
		}
		*/

		int i;
		int size = sizeof(ctrl_cmds) / sizeof(ctrl_cmds[0]);
		for (i = 0; i < size; ++i)
		{
			if (strcmp(ctrl_cmds[i].cmd, sess->cmd) == 0)
			{
				if (ctrl_cmds[i].cmd_handler != NULL)
				{
					//调用对应的命令处理函数
					ctrl_cmds[i].cmd_handler(sess);
				}
				else
				{
					ftp_reply(sess, FTP_COMMANDNOTIMPL, "Unimplement command.");
				}
				
				break;
			}
		}

		if (i == size)
		{
			ftp_reply(sess, FTP_BADCMD, "Unknown command.");
		}
	}
}

void ftp_reply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d %s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

void ftp_lreply(session_t *sess, int status, const char *text)
{
	char buf[1024] = {0};
	sprintf(buf, "%d-%s\r\n", status, text);
	writen(sess->ctrl_fd, buf, strlen(buf));
}

int list_common(session_t *sess, int detail)
{
	DIR *dir = opendir(".");
	if (dir == NULL)
	{
		return 0;
	}

	struct dirent *dt;
	struct stat sbuf;
	while ((dt = readdir(dir)) != NULL)
	{
		if (dt->d_name[0] == '.') 
		{
			continue;
		}
		
		char buf[1024] = {0};
		if (detail)
		{
			if (lstat(dt->d_name, &sbuf) < 0)
			{
				continue;
			}
			
			const char * perms = get_file_perms(&sbuf);
			
			int off = 0;
			off += sprintf(buf, "%s ", perms);
			off += sprintf(buf + off, " %3d %-8d %-8d ", sbuf.st_nlink, sbuf.st_uid, sbuf.st_gid);
			off += sprintf(buf + off, "%8lu ", (unsigned long)sbuf.st_size);
			
			const char * datebuf = get_file_modify_time(&sbuf);
			
			off += sprintf(buf + off, "%s ", datebuf);
			if (S_ISLNK(sbuf.st_mode))
			{
				//用tmp存放原来的文件
				char tmp[1024] = {0};
				readlink(dt->d_name, tmp, sizeof(tmp));
				off += sprintf(buf + off, "%s -> %s\r\n", dt->d_name, tmp);
			}
			else
			{
				off += sprintf(buf + off, "%s\r\n", dt->d_name);
			}
		}
		else
		{
			sprintf(buf, "%s\r\n", dt->d_name);
		}

		writen(sess->data_fd, buf, strlen(buf));
	}

	closedir(dir);

	return 1;
}

void ascii_recvfile_upload(session_t * sess, int fd, int * flag)
{
	int ret;
	char sendbuf[1024 + 1];
	while (1) 
	{
		memset(sendbuf, 0, sizeof(sendbuf));
		ret = my_readline(sess->data_fd, sendbuf, sizeof(sendbuf));
		if (ret == -1)
		{
			*flag = 0;
			break;
		}
		else if (ret == 0)
		{
			*flag = 1;
			break;
		}
		else 
		{
			int end = strlen(sendbuf) - 1;
			if (sendbuf[end - 1] == '\r'
				&& sendbuf[end] == '\n')
			{
				str_trim_crlf(sendbuf);
				sprintf(sendbuf + end - 1, "\n");
			}
			
			ret = writen(fd, sendbuf, strlen(sendbuf));
			if (ret != strlen(sendbuf))
			{
				*flag = 2;
				break;
			}
			
		}
	}
	close(fd);
}

void binary_recvfile_upload(session_t * sess, int fd, int * flag)
{
	int ret;
	char recvbuf[1024];
	while (1) 
	{
		memset(recvbuf, 0, sizeof(recvbuf));
		ret = readn(sess->data_fd, recvbuf, sizeof(recvbuf));
		if (ret == -1)
		{
			*flag = 0;
			break;
		}
		else if (ret == 0)
		{
			*flag = 1;
			break;
		}
		else 
		{
			ret = writen(fd, recvbuf, strlen(recvbuf));
			if (ret != strlen(recvbuf))
			{
				*flag = 2;
				break;
			}
			
		}
	}
	close(fd);
}

void upload_common(session_t * sess, int is_append)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	// 获取下载断点位置
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	// 打开文件
	int fd = open(sess->arg, O_CREAT | O_WRONLY, 0666);
	if (fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to create file");
		return;
	}
	
	int ret;
	//打开文件第一步：1.给文件上读锁
	
	ret = lock_file_write(fd);
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to lock file");
		return;
	}
	
	//打开文件第二步：2.判断要下载的文件类型，只有普通类型的文件才能下载
	
	struct stat sbuf;
	memset(&sbuf, 0, sizeof(sbuf));
	ret = fstat(fd, &sbuf);
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to fstat file.");
		return;
	}
	
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to recv nonregular file.");
		return;
	}
	
	//打开文件第三步：3.根据是否有断点位置，设置文件偏移量
	
	if (!is_append)
	{
		if (!offset)
		{
			ftruncate(fd, 0);
		}
		ret = lseek(fd, offset, SEEK_SET);
		printf("luowenguangoffset\n");
		if (ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to lseek file");
			return;
		}
	}
	else
	{
		ret = lseek(fd, 0, SEEK_END);
		if (ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to lseek file");
			return;
		}
	}
	
	//打开文件第四步：4.根据客户端给出的文件下载模式（是ASCII模式还是二进制模式），给出相应的应答
	int flag;
	if (sess->is_ascii)
	{
		if (offset || is_append)
		{
			ftp_reply(sess, FTP_FILEFAIL, "No support for resume of ASCII transfer.");
			return;
		}
		ftp_reply(sess, FTP_DATACONN, "Ok to send data.");
		ascii_recvfile_upload(sess, fd, &flag);
	}
	else 
	{
		if (offset > sbuf.st_size)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to send file.");
			return;
		}
		ftp_reply(sess, FTP_DATACONN, "Ok to send data.");
		binary_recvfile_upload(sess, fd, &flag);
	}
	
	
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	
	if (flag == 0)
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure reading data from network stream.");
	}
	else if (flag == 1)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else 
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure writing data to local file.");
	}
}

int port_active(session_t *sess)
{
	if (sess->port_addr)
	{
		if (pasv_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}

	return 0;
}

int pasv_active(session_t *sess)
{
	/*
	if (sess->pasv_listen_fd != -1)
	{
		if (port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;*/
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACTIVE);
	char res = priv_sock_get_result(sess->child_fd);
	printf("luowenguang7:%d\n", res);
	if (res == PRIV_SOCK_RESULT_OK)
	{
		printf("luowenguang8\n");
		if (port_active(sess))
		{
			fprintf(stderr, "both port an pasv are active");
			exit(EXIT_FAILURE);
		}
		return 1;
	}
	return 0;
}

int get_port_fd(session_t * sess)
{
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_GET_DATA_SOCK);
	unsigned short port = ntohs(sess->port_addr->sin_port);
	const char * addr = inet_ntoa(sess->port_addr->sin_addr);
	free(sess->port_addr);
	sess->port_addr = NULL;
	priv_sock_send_int(sess->child_fd, (int)port);
	priv_sock_send_buf(sess->child_fd, addr, strlen(addr));
	
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD) 
	{
		return 0;
	} 
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
		return 1;
	}
	return 0;
}

int get_pasv_fd(session_t * sess)
{
	printf("luowenguang1\n");
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_ACCEPT);
	
	char res = priv_sock_get_result(sess->child_fd);
	printf("res = %d\n", res);
	if (res == PRIV_SOCK_RESULT_BAD) 
	{
		return 0;
	} 
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		sess->data_fd = priv_sock_recv_fd(sess->child_fd);
		return 1;
	}
	return 0;
}

int get_transfer_fd(session_t *sess)
{
	// 检测是否收到PORT或者PASV命令
	if (!port_active(sess) && !pasv_active(sess))
	{
		ftp_reply(sess, FTP_BADSENDCONN, "Use PORT or PASV first.");
		return 0;
	}
	printf("luownguang2\n");
	// 如果是主动模式
	if (port_active(sess))
	{
		/*
		free(sess->port_addr);
		sess->port_addr = NULL;

		sess->data_fd = fd;*/
		return get_port_fd(sess);
	}
	printf("luownguang3\n");
	if (pasv_active(sess))
	{
		/*int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
		close(sess->pasv_listen_fd);
		sess->pasv_listen_fd = -1;

		if (fd == -1)
		{
			return 0;
		}

		sess->data_fd = fd;*/
		printf("luownguang4\n");
		return get_pasv_fd(sess);
	}
	return 0;
}

static void do_user(session_t *sess)
{
	//USER wgluohappy
	struct passwd *pw = getpwnam(sess->arg);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	//得到一个用户id作为中间传递值，既然这样，干吗不直接传递用户名？
	sess->uid = pw->pw_uid;
	ftp_reply(sess, FTP_GIVEPWORD, "Please specify the password.");
	
}

static void do_pass(session_t *sess)
{
	// PASS 123456
	struct passwd *pw = getpwuid(sess->uid);
	if (pw == NULL)
	{
		// 用户不存在
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	printf("name=[%s]\n", pw->pw_name);
	//根据用户名从影子文件中获取密码信息
	struct spwd *sp = getspnam(pw->pw_name);
	if (sp == NULL)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	// 将明文按照密文格式进行加密
	char *encrypted_pass = crypt(sess->arg, sp->sp_pwdp);
	// 验证密码
	if (strcmp(encrypted_pass, sp->sp_pwdp) != 0)
	{
		ftp_reply(sess, FTP_LOGINERR, "Login incorrect.");
		return;
	}

	umask(tunable_local_umask);
	setegid(pw->pw_gid);
	seteuid(pw->pw_uid);
	
	//到此已由一个root用户进程转变成一个普通用户进程
	chdir(pw->pw_dir);
	ftp_reply(sess, FTP_LOGINOK, "Login successful.");
}

static void do_cwd(session_t *sess)
{
	if (chdir(sess->arg) == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_cdup(session_t *sess)
{
	if (chdir("..") == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to change directory.");
		return;
	}
	ftp_reply(sess, FTP_CWDOK, "Directory successfully changed.");
}

static void do_quit(session_t *sess)
{
}

static void do_port(session_t *sess)
{
	//PORT 192,168,0,100,123,233
	unsigned int v[6];

	sscanf(sess->arg, "%u,%u,%u,%u,%u,%u", &v[2], &v[3], &v[4], &v[5], &v[0], &v[1]);
	sess->port_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
	memset(sess->port_addr, 0, sizeof(struct sockaddr_in));
	sess->port_addr->sin_family = AF_INET;
	unsigned char *p = (unsigned char *)&sess->port_addr->sin_port;
	p[0] = v[0];
	p[1] = v[1];

	p = (unsigned char *)&sess->port_addr->sin_addr.s_addr;
	p[0] = v[2];
	p[1] = v[3];
	p[2] = v[4];
	p[3] = v[5];

	ftp_reply(sess, FTP_PORTOK, "PORT command successful. Consider using PASV.");
}

static void do_pasv(session_t *sess)
{
	//Entering Passive Mode (192,168,244,100,101,46).
/*
	sess->pasv_listen_fd = tcp_server(tunable_listen_address, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		ERR_EXIT("getsockname");
	}
	*/
	unsigned short port;
	priv_sock_send_cmd(sess->child_fd, PRIV_SOCK_PASV_LISTEN);
	char res = priv_sock_get_result(sess->child_fd);
	if (res == PRIV_SOCK_RESULT_BAD)
	{
		return;
	}
	else if (res == PRIV_SOCK_RESULT_OK)
	{
		port = (unsigned short)priv_sock_get_int(sess->child_fd);
	}
	
	unsigned char * p = (unsigned char *)&port;
	
	in_addr_t s_addr = inet_addr(tunable_listen_address);
	unsigned char * q = (unsigned char *)&s_addr;
	
	char text[1024] = {0};
	sprintf(text, "Entering Passive Mode (%u,%u,%u,%u,%u,%u).", 
		q[0], q[1], q[2], q[3], p[0], p[1]);

	ftp_reply(sess, FTP_PASVOK, text);
}

static void do_type(session_t *sess)
{
	if (strcmp(sess->arg, "A") == 0)
	{
		sess->is_ascii = 1;
		ftp_reply(sess, FTP_TYPEOK, "Switching to ASCII mode.");
	}
	else if (strcmp(sess->arg, "I") == 0)
	{
		sess->is_ascii = 0;
		ftp_reply(sess, FTP_TYPEOK, "Switching to Binary mode.");
	}
	else
	{
		ftp_reply(sess, FTP_BADCMD, "Unrecognised TYPE command.");
	}

}

static void do_stru(session_t *sess)
{
}

static void do_mode(session_t *sess)
{
}

/*
 * 用于ascii文件的传输，但由于将ascii文件传输到客户端的时候，将所有的\n字符
 * 都转换成了\r\n（客户端的回车字符）字符，所以客户端传过来的断点位置和服务器
 * 源文件的传输断点位置不一致，如果硬性续传，将导致客户端下载下来的文件和服务
 * 器上源文件不一致，所以不支持ascii文件的断点续传
 */
void ascii_sendfile_download(session_t * sess, int fd, int * flag)
{
	int ret;
	char sendbuf[1024 + 1];
	while (1) 
	{
		memset(sendbuf, 0, sizeof(sendbuf));
		ret = my_readline(fd, sendbuf, sizeof(sendbuf));
		if (ret == -1)
		{
			*flag = 0;
			break;
		}
		else if (ret == 0)
		{
			*flag = 1;
			break;
		}
		else 
		{
			int end = strlen(sendbuf) - 1;
			if (sendbuf[end] == '\n')
			{
				//str_trim_crlf(sendbuf);
				sprintf(sendbuf + end, "\r\n");
			}
			
			ret = writen(sess->data_fd, sendbuf, strlen(sendbuf));
			if (ret != strlen(sendbuf))
			{
				*flag = 2;
				break;
			}
			
		}
	}
	close(fd);
}

/*
 * 用于二进制文件的传输，且支持断点续传
 **/
void binary_sendfile_download(session_t * sess, 
		int fd, long long bytes_to_send, int * flag)
{
	int ret;
	while (bytes_to_send)
	{
		int num_this_time = bytes_to_send > 4096? 4096 : bytes_to_send;
		ret = sendfile(sess->data_fd, fd, NULL, num_this_time);
		if (ret == -1)
		{
			*flag = 0;
			break;
		}
		else if (ret != num_this_time)
		{
			*flag = 2;
			break;
		}
		bytes_to_send -= num_this_time;
	}
	
	if (bytes_to_send == 0)
	{
		*flag = 1;
	}
	close(fd);
}

static void do_retr(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		return;
	}
	
	// 获取下载断点位置
	long long offset = sess->restart_pos;
	sess->restart_pos = 0;
	
	// 打开文件
	int fd = open(sess->arg, O_RDONLY);
	if (fd == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to open file");
		return;
	}
	
	int ret;
	//打开文件第一步：1.给文件上读锁
	
	ret = lock_file_read(fd);
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to lock file");
		return;
	}
	
	//打开文件第二步：2.判断要下载的文件类型，只有普通类型的文件才能下载
	
	struct stat sbuf;
	memset(&sbuf, 0, sizeof(sbuf));
	ret = fstat(fd, &sbuf);
	if (ret == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to fstat file.");
		return;
	}
	
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Failed to send nonregular file.");
		return;
	}
	
	//打开文件第三步：3.根据是否有断点位置，设置文件偏移量
	
	if (offset)
	{
		ret = lseek(fd, offset, SEEK_SET);
		if (ret == -1)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to lseek file");
			return;
		}
	}
	
	//打开文件第四步：4.根据客户端给出的文件下载模式（是ASCII模式还是二进制模式），给出相应的应答
	char text[1024] = {0};
	if (sess->is_ascii)
	{
		if (offset)
		{
			ftp_reply(sess, FTP_FILEFAIL, "No support for resume of ASCII transfer.");
			return;
		}
		sprintf(text, "Opening ASCII mode data connection for %s (%lld bytes).", 
				sess->arg, (long long)sbuf.st_size);
	}
	else 
	{
		if (offset > sbuf.st_size)
		{
			ftp_reply(sess, FTP_FILEFAIL, "Failed to send file.");
			return;
		}
		sprintf(text, "Opening BINARY mode data connection for %s (%lld bytes).", 
				sess->arg, (long long)sbuf.st_size);
	}
	ftp_reply(sess, FTP_DATACONN, text);
	
	//打开文件第五步：5.根据相应的下载模式，向客户端发送数据
	int flag;
	if (sess->is_ascii)
	{
		ascii_sendfile_download(sess, fd, &flag);
	}
	else 
	{
		long long bytes_to_send = sbuf.st_size - offset;
		binary_sendfile_download(sess, fd, bytes_to_send, &flag);
	}
	
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	
	if (flag == 0)
	{
		ftp_reply(sess, FTP_BADSENDNET, "Failure reading data from local file.");
	}
	else if (flag == 1)
	{
		ftp_reply(sess, FTP_TRANSFEROK, "Transfer complete.");
	}
	else 
	{
		ftp_reply(sess, FTP_BADSENDFILE, "Failure writing data to network stream.");
	}
}

static void do_stor(session_t *sess)
{
	upload_common(sess, 0);
}

static void do_appe(session_t *sess)
{
	upload_common(sess, 1);
}

static void do_list(session_t *sess)
{
	// 创建数据连接
	if (get_transfer_fd(sess) == 0)
	{
		printf("luowenguang\n");
		return;
	}
	ftp_reply(sess, FTP_DATACONN, "Here comes the directory listing.");

	// 传输列表
	if (strcmp(sess->cmd, "LIST") == 0)
	{
		list_common(sess, 1);
	}
	else
	{
		list_common(sess, 0);
	}
	// 关闭数据套接字
	close(sess->data_fd);
	sess->data_fd = -1;
	// 226
	ftp_reply(sess, FTP_TRANSFEROK, "Directory send OK.");
}

static void do_rest(session_t *sess)
{
	sess->restart_pos = str_to_longlong(sess->arg);
	char text[1024] = {0};
	sprintf(text, "Restart position accepted (%lld).", sess->restart_pos);
	ftp_reply(sess, FTP_RESTOK, text);
}

static void do_abor(session_t *sess)
{
}

static void do_pwd(session_t *sess)
{
	char text[1024] = {0};
	char dir[1024 + 1] = {0};
	getcwd(dir, 1024);
	sprintf(text, "\"%s\"", dir);

	ftp_reply(sess, FTP_PWDOK, text);
}

static void do_mkd(session_t *sess)
{
	if (mkdir(sess->arg, 0777) == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "Create directory operation failed.");
		return;
	} 
	
	char text[1024] = {0};
	if (sess->arg[0] == '/')
	{
		sprintf(text, "\"%s\" created", sess->arg);
	}
	else 
	{
		char dir[1024 + 1] = {0};
		getcwd(dir, 1024);
		if (dir[strlen(dir) - 1] == '/')
		{
			sprintf(text, "\"%s%s\" created", dir, sess->arg);
		}
		else
		{
			sprintf(text, "\"%s/%s\" created", dir, sess->arg);
		}
	}
	
	ftp_reply(sess, FTP_MKDIROK, text);
}

static void do_rmd(session_t *sess)
{
	if (rmdir(sess->arg) == -1)
	{ 
		ftp_reply(sess, FTP_FILEFAIL, "Remove directory operation failed.");
		return;
	}

	ftp_reply(sess, FTP_RMDIROK, "Remove directory operation successful.");
}

static void do_dele(session_t *sess)
{
	if (unlink(sess->arg) == -1)
	{ 
		ftp_reply(sess, FTP_FILEFAIL, "Delete operation failed.");
		return;
	}

	ftp_reply(sess, FTP_DELEOK, "Delete operation successful.");
}

static void do_rnfr(session_t *sess)
{
	sess->file_old_name = (char *)malloc(strlen(sess->arg) + 1);
	memset(sess->file_old_name, 0, strlen(sess->arg) + 1);
	strcpy(sess->file_old_name, sess->arg);
	ftp_reply(sess, FTP_RNFROK, "Ready for RNTO.");
}

static void do_rnto(session_t *sess)
{
	if (sess->file_old_name == NULL) 
	{
		ftp_reply(sess, FTP_NEEDRNFR, "RNFR required first.");
		return;
	}
	
	rename(sess->file_old_name, sess->arg);
	ftp_reply(sess, FTP_RENAMEOK, "Rename successful.");
	free(sess->file_old_name);
	sess->file_old_name = NULL;
}

static void do_site(session_t *sess)
{
}

static void do_syst(session_t *sess)
{
	ftp_reply(sess, FTP_SYSTOK, "UNIX Type: L8");
}

static void do_feat(session_t *sess)
{
	ftp_lreply(sess, FTP_FEAT, "Features:");
	writen(sess->ctrl_fd, " EPRT\r\n", strlen(" EPRT\r\n"));
	writen(sess->ctrl_fd, " EPSV\r\n", strlen(" EPSV"));
	writen(sess->ctrl_fd, " MDTM\r\n", strlen(" MDTM\r\n"));
	writen(sess->ctrl_fd, " PASV\r\n", strlen(" PASV\r\n"));
	writen(sess->ctrl_fd, " REST STREAM\r\n", strlen(" REST STREAM\r\n"));
	writen(sess->ctrl_fd, " SIZE\r\n", strlen(" SIZE\r\n"));
	writen(sess->ctrl_fd, " TVFS\r\n", strlen(" TVFS\r\n"));
	writen(sess->ctrl_fd, " UTF8\r\n", strlen(" UTF8\r\n"));
	ftp_reply(sess, FTP_FEAT, "End");
}

static void do_size(session_t *sess)
{
	struct stat sbuf;
	memset(&sbuf, 0, sizeof(sbuf));
	if (stat(sess->arg, &sbuf) == -1)
	{
		ftp_reply(sess, FTP_FILEFAIL, "SIZE operation failed.");
		return;
	}
	
	if (!S_ISREG(sbuf.st_mode))
	{
		ftp_reply(sess, FTP_FILEFAIL, "Could not get file size.");
		return;
	}
	
	char text[1024] = {0};
	sprintf(text, "%lld", (long long)sbuf.st_size);
	ftp_reply(sess, FTP_SIZEOK, text);
}

static void do_stat(session_t *sess)
{
}

static void do_noop(session_t *sess)
{
}

static void do_help(session_t *sess)
{
}


#include "privparent.h"
#include "privsock.h"
#include "sysutil.h"
#include "tunable.h"

static void privop_pasv_get_data_sock(session_t *sess);
static void privop_pasv_active(session_t *sess);
static void privop_pasv_listen(session_t *sess);
static void privop_pasv_accept(session_t *sess);

/* capset是一个原始的内核接口，用于给一般进程设置特殊权限；
 * 但在头文件linux/capability.h当中并没有提供该函数的声明，所以需自己给出声明；
 * 通过调用syscall函数，并指定相应接口的代码，可以调用相应的内核接口
 */
int capset(cap_user_header_t hdrp, const cap_user_data_t datap)
{
	return syscall(SYS_capset, hdrp, datap);
}

void minimize_privilege(void)
{
	struct passwd *pw = getpwnam("nobody");
	if (pw == NULL)
		return;

	if (setegid(pw->pw_gid) < 0)
		ERR_EXIT("setegid");
	if (seteuid(pw->pw_uid) < 0)
		ERR_EXIT("seteuid");
	
	// 到此已由一个root用户进程转变成一个nobdoy用户进程
	struct __user_cap_header_struct _header;
	struct __user_cap_data_struct _data;
	memset(&_header, 0, sizeof(struct __user_cap_header_struct));
	memset(&_data, 0, sizeof(struct __user_cap_data_struct));
	
	_header.version = _LINUX_CAPABILITY_VERSION_1;
	_header.pid = 0;	//因为是给相应进程设置特权，所以不需要指定进程ID
	
	__u32 privilegemask = 0;
	privilegemask |= (1 << CAP_NET_BIND_SERVICE);
	_data.effective = _data.permitted = privilegemask;
	_data.inheritable = 0;	//不允许该进程获得权限被继承下去
	
 	capset(&_header, &_data);
}

void handle_parent(session_t *sess)
{
	minimize_privilege();	//使nobody用户进程的权限最小，仅仅获得绑定特权端口的权限
	char cmd;
	while (1)
	{
		cmd = priv_sock_get_cmd(sess->parent_fd);
		// 解析内部命令
		// 处理内部命令
		switch (cmd)
		{
		case PRIV_SOCK_GET_DATA_SOCK:
			privop_pasv_get_data_sock(sess);
			break;
		case PRIV_SOCK_PASV_ACTIVE:
			privop_pasv_active(sess);
			break;
		case PRIV_SOCK_PASV_LISTEN:
			privop_pasv_listen(sess);
			break;
		case PRIV_SOCK_PASV_ACCEPT:
			privop_pasv_accept(sess);
			break;
		
		}
	}
}

static void privop_pasv_get_data_sock(session_t *sess)
{
	/*
		socket
		bind 20
		connect
		*/
		// tcp_client(20);
		/*
	*/
	char ip[16] = {0};
	unsigned short port = (unsigned short)priv_sock_get_int(sess->parent_fd);
	priv_sock_recv_buf(sess->parent_fd, ip, sizeof(ip));
	
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = inet_addr(ip);
	
	int fd = tcp_client(20);
	if (fd == -1) 
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	
	if (connect_timeout(fd, &addr, tunable_connect_timeout) < 0)
	{
		close(fd);
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}
	
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}

static void privop_pasv_active(session_t *sess)
{
	if (sess->pasv_listen_fd != -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
 		return;
	}
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
}

static void privop_pasv_listen(session_t *sess)
{
	sess->pasv_listen_fd = tcp_server(tunable_listen_address, 0);
	struct sockaddr_in addr;
	socklen_t addrlen = sizeof(addr);
	if (getsockname(sess->pasv_listen_fd, (struct sockaddr *)&addr, &addrlen) < 0)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		ERR_EXIT("getsockname");
	}
	
	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_int(sess->parent_fd, (int)addr.sin_port);
}

static void privop_pasv_accept(session_t *sess)
{
	int fd = accept_timeout(sess->pasv_listen_fd, NULL, tunable_accept_timeout);
	close(sess->pasv_listen_fd);
	sess->pasv_listen_fd = -1;

	if (fd == -1)
	{
		priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_BAD);
		return;
	}

	priv_sock_send_result(sess->parent_fd, PRIV_SOCK_RESULT_OK);
	priv_sock_send_fd(sess->parent_fd, fd);
	close(fd);
}


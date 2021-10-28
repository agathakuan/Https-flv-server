#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <signal.h>
#include <errno.h>
#include <getopt.h>

#include <openssl/ssl.h>
#include <openssl/err.h>

#define DEBUG
#ifdef DEBUG
#define LOG(format, args...) fprintf(stderr, "[%s:%d]" format, __func__, __LINE__, ##args);
#else
#define LOG(format, args...)
#endif
#define ERR(format, args...) fprintf(stderr, "[%s:%d]" format, __func__, __LINE__, ##args);
#define INFO(format, args...) fprintf(stderr, "[%s:%d]" format, __func__, __LINE__, ##args);

int run_flag = 0;
int srv_soc = 0, acpt_soc = 0;
#define HTTP_BUF_SIZE 1024
#define HTTP_FILENAME_LEN 256

typedef struct {
	int port;
	char cert_file[64];
	char key_file[64];
	char src_file[64];
} HttpsServerInfo;

SSL_CTX *create_context()
{
	const SSL_METHOD *method;
	SSL_CTX *ctx;

	method = SSLv23_server_method();

	ctx = SSL_CTX_new(method);
	if (!ctx) {
		ERR("Unable to create SSL context");
		ERR_print_errors_fp(stderr);
		return (SSL_CTX *)NULL;
	}

	return ctx;
}

int configure_context(SSL_CTX *ctx, char *cert_path, char *key_path)
{
	if ((cert_path == NULL) || (key_path == NULL)) {
		ERR("failed to get .pem\r\n");
		return -EACCES;
	}

	SSL_CTX_set_ecdh_auto(ctx, 1);

	/* Set the key and cert */
	if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		ERR("Failed use cert file\r\n");
		return -EACCES;
	}

	if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0) {
		ERR_print_errors_fp(stderr);
		ERR("Failed use key file\r\n");
		return -EACCES;
	}

	return 0;
}

void init_openssl()
{
	SSL_load_error_strings();
	OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl()
{
	EVP_cleanup();
}

int create_socket(int port_num)
{
	struct sockaddr_in serv_addr;
	unsigned short port = port_num;
	int result = 0;
	int server_soc;

	server_soc = socket(PF_INET, SOCK_STREAM, 0);
	if (server_soc == -1) {
		ERR("[Web] socket() Fails, error = %d\n", server_soc);
		return -EIO;
	}

	int reuseaddr = 1;
	int len = sizeof(reuseaddr);
	int ret = setsockopt(server_soc, SOL_SOCKET, SO_REUSEADDR, &reuseaddr, len);
	if (ret == -1) {
		fprintf(stderr, "Failed to set re-use addr\r\n");
	}

	serv_addr.sin_family = AF_INET;
	serv_addr.sin_port = htons(port);
	serv_addr.sin_addr.s_addr = htonl(INADDR_ANY);

	result = bind(server_soc, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
	if (result == -1) {
		close(server_soc);
		ERR("[Web] Fail to bind, error = %d\n", result);
		return -EIO;
	}

	result = listen(server_soc, SOMAXCONN);
	LOG("[Web] The server is running ... ...\n");

	return server_soc;
}

void handleSignal(int signo)
{
	if (signo == SIGINT) {
		ERR("received SIGINT\n");
		run_flag = 0;
		ERR("close port :%d , %d\n", srv_soc, acpt_soc);
	}

	return;
}

void *runHttpsServer(void *argv)
{
	HttpsServerInfo *info = (HttpsServerInfo *)argv;

	LOG("Assigned port %d, src:%s\r\ncert path:%s\r\nkey path:%s\r\n", info->port, info->src_file, info->cert_file,
	    info->key_file);

	SSL_CTX *ctx;

	struct sockaddr_in serv_addr;
	struct sockaddr_in from_addr;
	char recv_buf[HTTP_BUF_SIZE];
	char read_buf[HTTP_BUF_SIZE];
	socklen_t from_len = sizeof(from_addr);
	int result = 0, recv_len;

	init_openssl();
	ctx = create_context();
	configure_context(ctx, &info->cert_file[0], &info->key_file[0]);
	srv_soc = create_socket(info->port);

	while (run_flag) {
		struct sockaddr_in addr;
		uint len = sizeof(addr);
		SSL *ssl;

		acpt_soc = accept(srv_soc, (struct sockaddr *)&from_addr, &from_len);
		if (acpt_soc < 0) {
			perror("Unable to accept");
			break;
		}

		INFO("[Web] Accepted address:[%s], port:[%d]\n", inet_ntoa(from_addr.sin_addr),
		     ntohs(from_addr.sin_port));

		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, acpt_soc);

		if (SSL_accept(ssl) <= 0) {
			ERR_print_errors_fp(stderr);
		}

		/*seperate to single thread*/
		recv_len = SSL_read(ssl, recv_buf, HTTP_BUF_SIZE);
		if (recv_len == -1) {
			close(acpt_soc);
			SSL_shutdown(ssl);
			SSL_free(ssl);
			ERR("[Web] Fail to recv, error = %d\n", recv_len);
			break;
		}

		LOG("%s", recv_buf);
		recv_buf[recv_len] = 0;

		char http_res_hdr_tmpl[] = "HTTP/1.1 200 OK\r\n"
		                           "Server: Augentix <0.1>\r\n"
		                           "Content-Type:  video/x-flv\r\n"
		                           "Connection: keep-alive\r\n"
		                           "Expires: -1\r\n"
		                           "Access-Control-Allow-Origin: *\r\n"
		                           "Access-Control-Allow-Credentials: true\r\n\r\n";
		SSL_write(ssl, http_res_hdr_tmpl, strlen(http_res_hdr_tmpl));

		FILE *fp = fopen(info->src_file, "rb+");
		fseek(fp, 0, SEEK_END);
		int file_len = ftell(fp);
		fseek(fp, 0, SEEK_SET);
		int read_len = 0;
		int send_len = 0;
		do {
			read_len = fread(read_buf, sizeof(char), HTTP_BUF_SIZE, fp);
			if (read_len > 0) {
				send_len = SSL_write(ssl, read_buf, read_len);

				if (send_len == -1) {
					ERR("[Web] Fail to send, error = %d\n", send_len);
					break;
				}
				file_len -= read_len;
			}
		} while (((read_len > 0) && (file_len > 0)) && (run_flag));

		fclose(fp);
		LOG("[Web] send finish\n");

		SSL_shutdown(ssl);
		SSL_free(ssl);
		close(acpt_soc);
	}

	SSL_CTX_free(ctx);
	cleanup_openssl();

	return NULL;
}

void help()
{
	printf("Usage\r\n");
	printf("-p port number\r\n");
	printf("-s flv format src file\r\n");
	printf("-c cert.pem file\r\n");
	printf("-k private key file\r\n");
	printf("-h help");
}

int main(int argc, char **argv)
{
	if (signal(SIGINT, handleSignal) == SIG_ERR) {
		ERR("\ncan't catch SIGINT\n");
	}
	char src_file[64];
	char cert_file[64];
	char key_file[64];
	int port = 8443;
	int c = 0;

	while ((c = getopt(argc, argv, "hc:k:s:p:")) != -1) {
		switch (c) {
		case 'h':
			help();
			exit(1);
			break;
		case 'p':
			port = atoi(argv[optind - 1]);
			break;
		case 'c':
			snprintf(&cert_file[0], 64, "%s", argv[optind - 1]);
			break;
		case 'k':
			snprintf(&key_file[0], 64, "%s", argv[optind - 1]);
			break;
		case 's':
			snprintf(&src_file[0], 64, "%s", argv[optind - 1]);
			break;
		default:
			help();
			exit(1);
		}
	}

	HttpsServerInfo server_info;
	server_info.port = port;
	memcpy(&server_info.cert_file[0], &cert_file[0], sizeof(cert_file));
	memcpy(&server_info.key_file[0], &key_file[0], sizeof(key_file));
	memcpy(&server_info.src_file[0], &src_file[0], sizeof(src_file));

	if ((access(src_file, F_OK) == -1) || (access(key_file, F_OK) == -1) || (access(cert_file, F_OK) == -1)) {
		ERR("File not exist\r\n");
		return -EPERM;
	}

	run_flag = 1;
	pthread_t t0;
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);

	if (pthread_create(&t0, &attr, runHttpsServer, (void *)&server_info) != 0) {
		ERR("failed to create thread\r\n");
	}
	pthread_attr_destroy(&attr);

	if (pthread_setname_np(t0, "https-flv") != 0) {
		ERR("failed to set thread name\r\n");
	}

	while (run_flag) {
		sleep(2);
	}

	return 0;
}

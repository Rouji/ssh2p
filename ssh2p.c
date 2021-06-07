#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <curl/curl.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <libssh/server.h>

static const char* DEFAULT_PORT = "22";
static const char* DEFAULT_LISTEN_IP = "0.0.0.0";
static const char* DEFAULT_FORM_FIELD = "file";
static const char* DEFAULT_FILENAME = "file";
static const char* DEFAULT_RSAKEY = "id_rsa";
static const int DEFAULT_TIMEOUT = 5;

static const char* err_recv_timeout = "Error: receive timeout\n";
static const char* err_post = "Error: POST to upstream failed\n";

struct curl_response
{
    char* data;
    size_t size;
};

struct client_connection
{
    const char* upstream;
    const char* form_field;
    const char* filename;
    ssh_session sshsession;
    ssh_channel sshchannel;
    CURL* curl;
    char ip[INET6_ADDRSTRLEN];
    struct curl_response resp;
    const char* err;
};

void curl_close_socket(CURL* curl)
{
    curl_socket_t sock;
    curl_easy_getinfo(curl, CURLINFO_ACTIVESOCKET, &sock);
    close(sock);
}

size_t curl_read_cb(char* buffer, size_t size, size_t nitems, void* user)
{
    struct client_connection* cc = (struct client_connection*)user;
    size_t realsize = size * nitems;

    int ret = ssh_channel_read(cc->sshchannel, buffer, realsize, 0);
    if (ret == SSH_ERROR)
    {
        printf("%s\tssh_channel_read() failed\n", cc->ip);
        curl_close_socket(cc->curl);
        return CURL_READFUNC_ABORT;
    }
    if (ret == 0 && !ssh_channel_is_eof(cc->sshchannel))
    {
        printf("%s\tssh_channel_read timed out\n", cc->ip);
        cc->err = err_recv_timeout;
        curl_close_socket(cc->curl);
        return CURL_READFUNC_ABORT;
    }
    return ret;
}

size_t curl_write_cb(void* data, size_t size, size_t nitems, void* user)
{
    struct client_connection* cc = (struct client_connection*)user;
    size_t realsize = size * nitems;
    if (realsize == 0)
    {
        return 0;
    }
    void* new = realloc(cc->resp.data, cc->resp.size + realsize + 1);
    if (new == NULL)
    {
        fprintf(stderr, "%s\trealloc() failed: %s\n", cc->ip, strerror(errno));
        curl_close_socket(cc->curl);
        return -1;
    }
    cc->resp.data = new;
    memcpy(cc->resp.data + cc->resp.size, data, realsize);
    cc->resp.size += realsize;
    cc->resp.data[cc->resp.size] = 0;
    return realsize;
}

void* thread(void* arg)
{
    struct client_connection* cc = (struct client_connection*) arg;
    int exit_status = 1;

    if (ssh_handle_key_exchange(cc->sshsession) != 0)
    {
        goto cleanup;
    }

    int authed = 0;
    int type;
    int subtype;
    ssh_message sshmsg;
    do
    {
        if ((sshmsg = ssh_message_get(cc->sshsession)) == NULL)
        {
            goto cleanup;
        }

        type = ssh_message_type(sshmsg);
        subtype = ssh_message_subtype(sshmsg);
        switch (type)
        {
            case SSH_REQUEST_AUTH:
                ssh_message_auth_reply_success(sshmsg, 0);
                authed = 1;
                break;
            case SSH_REQUEST_CHANNEL_OPEN:
                if (subtype == SSH_CHANNEL_SESSION)
                    cc->sshchannel = ssh_message_channel_request_open_reply_accept(sshmsg);
                break;
            case SSH_REQUEST_CHANNEL:
                if (subtype == SSH_CHANNEL_REQUEST_SHELL || subtype == SSH_CHANNEL_REQUEST_EXEC)
                    ssh_message_channel_request_reply_success(sshmsg);
                break;
            default:
                if (!authed)
                    ssh_message_auth_set_methods(sshmsg, SSH_AUTH_METHOD_NONE);
                ssh_message_reply_default(sshmsg);
        }
        ssh_message_free(sshmsg);
    } while (cc->sshchannel == NULL);

    struct sockaddr_in client_addr;
    socklen_t addrlen = sizeof(client_addr);
    getpeername(ssh_get_fd(cc->sshsession), (struct sockaddr*)&client_addr, &addrlen);
    char xff[INET6_ADDRSTRLEN + 20];
    strcpy(cc->ip, inet_ntoa(client_addr.sin_addr));
    snprintf(xff, sizeof(xff), "X-Forwarded-For: %s", cc->ip);

    CURL* curl = cc->curl = curl_easy_init();
    struct curl_slist* headers = curl_slist_append(NULL, xff);
    curl_mime* mime = curl_mime_init(curl);
    curl_mimepart* part = curl_mime_addpart(mime);
    curl_mime_name(part, cc->form_field);
    curl_mime_filename(part, cc->filename);
    curl_mime_data_cb(part, -1, curl_read_cb, NULL, NULL, cc); // -1 -> chunked
    curl_easy_setopt(curl, CURLOPT_URL, cc->upstream);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, curl_write_cb);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, cc);
    CURLcode curl_res = curl_easy_perform(curl);
    curl_mime_free(mime);
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);

    int sent;
    if (curl_res == CURLE_ABORTED_BY_CALLBACK && cc->err != NULL)
    {
        sent = ssh_channel_write(cc->sshchannel, cc->err, strlen(cc->err)+1);
    }
    else if (curl_res != CURLE_OK)
    {
        fprintf(stderr, "%s\tUnexpected curl error: %s\n", cc->ip, curl_easy_strerror(curl_res));
        sent = ssh_channel_write(cc->sshchannel, err_post, strlen(err_post)+1);
    }
    else
    {
        int code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &code);
        sent = (code == 200 ? ssh_channel_write : ssh_channel_write_stderr)(cc->sshchannel, cc->resp.data, cc->resp.size);
        exit_status = code != 200;
    }
    if (sent == SSH_ERROR)
    {
        printf("%s\nssh_channel_write() failed\n", cc->ip);
    }

cleanup:
    ssh_channel_send_eof(cc->sshchannel);
    ssh_channel_request_send_exit_status(cc->sshchannel, exit_status);
    ssh_channel_close(cc->sshchannel);
    ssh_disconnect(cc->sshsession);
    ssh_free(cc->sshsession);
    free(cc->resp.data);
    free(cc);
    return 0;
}

void print_usage(const char* arg0)
{
    printf(
        "Usage: %s [OPTIONS] upstream_url\n\n"
        "OPTIONS:\n"
        "  -l <listen_ip>    IP to listen on (default: %s)\n"
        "  -p <listen_port>  port to listen on (default: %s)\n"
        "  -f <form_field>   name of the HTML form field for the uploaded file (default: %s)\n"
        "  -n <filename>     name of the uploaded file (default: %s)\n"
        "  -t <timeout>      SSH receive timeout in seconds (default: %d)\n"
        "  -r <rsa_key>      RSA ID file (default: %s)\n",
        arg0,
        DEFAULT_LISTEN_IP,
        DEFAULT_PORT,
        DEFAULT_FORM_FIELD,
        DEFAULT_FILENAME,
        DEFAULT_TIMEOUT,
        DEFAULT_RSAKEY);
}

int main(int argc, char* argv[])
{
    const char* arg_listen_ip = DEFAULT_LISTEN_IP;
    const char* arg_port = DEFAULT_PORT;
    const char* arg_upstream_url;
    const char* arg_form_field = DEFAULT_FORM_FIELD;
    const char* arg_filename = DEFAULT_FILENAME;
    const char* arg_rsakey = DEFAULT_RSAKEY;
    int arg_timeout = DEFAULT_TIMEOUT;
    int opt;
    while ((opt = getopt(argc, argv, "l:p:t:f:n:r:")) != -1)
    {
        switch (opt)
        {
            case 'l': arg_listen_ip = optarg; break;
            case 'p': arg_port = optarg; break;
            case 'f': arg_form_field = optarg; break;
            case 'n': arg_filename = optarg; break;
            case 'r': arg_rsakey = optarg; break;
            case 't': arg_timeout = atoi(optarg); break;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    if (optind >= argc)
    {
        print_usage(argv[0]);
        return 1;
    }
    arg_upstream_url = argv[optind];

    if (ssh_init() < 0)
    {
        fprintf(stderr, "ssh_init() failed\n");
        return 1;
    }

    ssh_bind sshbind;
    if ((sshbind = ssh_bind_new()) == NULL)
    {
        fprintf(stderr, "ssh_bind_new() failed\n");
        ssh_finalize();
        return 1;
    }

    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDADDR, arg_listen_ip);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_BINDPORT_STR, arg_port);
    ssh_bind_options_set(sshbind, SSH_BIND_OPTIONS_RSAKEY, arg_rsakey);

    if (ssh_bind_listen(sshbind) < 0)
    {
        fprintf(stderr, "ssh_bind_listen() failed: %s\n", ssh_get_error(sshbind));
        ssh_bind_free(sshbind);
        ssh_finalize();
        return 1;
    }

    curl_global_init(CURL_GLOBAL_ALL);
    signal(SIGPIPE, SIG_IGN);

    while (1)
    {
        struct client_connection* cc = calloc(1, sizeof(*cc));
        cc->upstream = arg_upstream_url;
        cc->filename = arg_filename;
        cc->form_field = arg_form_field;

        if ((cc->sshsession = ssh_new()) == NULL)
        {
            fprintf(stderr, "ssh_new() failed\n");
            goto cleanup;
        }
        if (ssh_bind_accept(sshbind, cc->sshsession) == SSH_ERROR)
        {
            fprintf(stderr, "ssh_bind_accept() failed: %s\n", ssh_get_error(sshbind));
            goto cleanup;
        }

        ssh_options_set(cc->sshsession, SSH_OPTIONS_TIMEOUT, &arg_timeout);

        pthread_t t;
        if (pthread_create(&t, NULL, thread, cc) != 0)
        {
            fprintf(stderr, "pthread_create() failed\n");
            goto cleanup;
        }
        pthread_detach(t);
        continue;

cleanup:
        ssh_free(cc->sshsession);
        free(cc);
    }

    return 0;
}

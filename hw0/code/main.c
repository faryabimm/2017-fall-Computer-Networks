#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <pthread.h>
#include <string.h>

#define ERROR (-1)
#define PORT_NUMBER 1234
#define SERVER_ADDRESS "0.0.0.0"
#define CONNECTION_QUEUE_LENGTH 1
#define BUFFER_SIZE 4       // support for UTF-8 characters


#define VERBOSE 0
#define VERBOSE_PROMPT(message, stream) if(VERBOSE) fprintf(stream, "%s\n", message);

typedef struct thread_data {
    FILE *file_descriptor;
    int socket_descriptor;
} thread_data;

void server_mode();

void client_mode(const char *IP_Address, int port_number);

void *receiver_thread(void *arguments);

void *transmitter_thread(void *arguments);

size_t read_line(char *buffer, size_t buffer_size, FILE *file_descriptor);

int main(int argc, char **argv) {

    if (argc <= 1) {
        server_mode();                              // server mode
    } else if (argc == 3) {
        if (strcmp(argv[1], "localhost") == 0) {    // client mode
            client_mode("127.0.0.1", atoi(argv[2]));
        } else {
            client_mode(argv[1], atoi(argv[2]));
        }
    } else {
        VERBOSE_PROMPT("Unknown argument", stdout)  // error
    }
}

void server_mode() {

    VERBOSE_PROMPT("SERVER MODE", stderr)
    VERBOSE_PROMPT("CREATING SOCKET", stderr)

    int server_socket_fd = socket(AF_INET,      /*IF_INET for IPv4, IF_INET6 for IPv6*/
                                  SOCK_STREAM,  /*SOCK_STREAM for TCP, SOCK_DGRAM for UDP*/
                                  IPPROTO_IP    /*IP PROTOCOL*/
    );

    if (server_socket_fd == 0) {
        VERBOSE_PROMPT("SOCKET CREATION FAILED", stderr)
        exit(EXIT_FAILURE);
    }


    VERBOSE_PROMPT("SETTING SOCKET OPTIONS", stderr)
    int socket_options = 1;

    int set_socket_status = setsockopt(server_socket_fd,
                                       SOL_SOCKET,
                                       SO_REUSEADDR | SO_REUSEPORT,
                                       &socket_options,
                                       sizeof(socket_options)
    );

    if (set_socket_status == ERROR) {
        VERBOSE_PROMPT("SETTING SOCKET OPTIONS FAILED", stderr)
        exit(EXIT_FAILURE);
    }


    VERBOSE_PROMPT("BINDING SOCKET", stderr)


    struct sockaddr_in address;
    socklen_t address_length = sizeof(address);
    address.sin_family = AF_INET;
    address.sin_port = htons(PORT_NUMBER);
    address.sin_addr.s_addr = inet_addr(SERVER_ADDRESS);

    int bind_status = bind(server_socket_fd,
                           (struct sockaddr *) &address,
                           address_length
    );

    if (bind_status < 0) {
        VERBOSE_PROMPT("SOCKET BINDING FAILED", stderr)
        exit(EXIT_FAILURE);
    }


    VERBOSE_PROMPT("LISTENING ON SOCKET", stderr)
    int listen_status = listen(server_socket_fd, CONNECTION_QUEUE_LENGTH);

    if (listen_status == ERROR) {
        VERBOSE_PROMPT("SOCKET LISTENING FAILED", stderr)
        exit(EXIT_FAILURE);
    }

    while (1) {

        VERBOSE_PROMPT("WAITING FOR CLIENT", stderr)

        int new_socket_fd = accept(server_socket_fd,
                                   (struct sockaddr *) &address,
                                   &address_length
        );

        VERBOSE_PROMPT("CLIENT ARRIVED AND ACCEPTED", stderr)


        if (new_socket_fd < 0) {
            VERBOSE_PROMPT("SOCKET ACCEPTING FAILED", stderr)
            exit(EXIT_FAILURE);
        }

        VERBOSE_PROMPT("STARTING THREADS", stderr)


        pthread_t transmitter;
        thread_data transmitter_data;
        transmitter_data.file_descriptor = stdin;
        transmitter_data.socket_descriptor = new_socket_fd;

        pthread_create(&transmitter, NULL, transmitter_thread, &transmitter_data);


        pthread_t receiver;
        thread_data receiver_data;
        receiver_data.file_descriptor = stdout;
        receiver_data.socket_descriptor = new_socket_fd;

        pthread_create(&receiver, NULL, receiver_thread, &receiver_data);

        pthread_join(receiver, NULL);
//        pthread_join(transmitter, NULL);
        shutdown(new_socket_fd, SHUT_WR);
        pthread_cancel(receiver);
        pthread_cancel(transmitter);

        VERBOSE_PROMPT("\nCLIENT DISCONNECTED", stderr)
    }
}

void client_mode(const char *IP_Address, int port_number) {

    VERBOSE_PROMPT("CREATING SOCKET", stderr)

    int socket_fd = socket(AF_INET,      /*IF_INET for IPv4, IF_INET6 for IPv6*/
                           SOCK_STREAM,  /*SOCK_STREAM for TCP, SOCK_DGRAM for UDP*/
                           0             /*IP PROTOCOL*/
    );

    if (socket_fd < 0) {
        VERBOSE_PROMPT("SOCKET CREATION FAILED", stderr)
        exit(EXIT_FAILURE);
    }


    VERBOSE_PROMPT("CHECKING ADDRESS", stderr)

    struct sockaddr_in address;
    memset(&address, '0', sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short int) port_number);

    int address_status = inet_pton(AF_INET, IP_Address, &address.sin_addr);

    if (address_status <= 0) {
        VERBOSE_PROMPT("INVALID ADDRESS", stderr)
        exit(EXIT_FAILURE);
    }

    VERBOSE_PROMPT("CONNECTING TO SERVER", stderr)

    int connection_status = connect(socket_fd, (struct sockaddr *) &address, sizeof(address));

    if (connection_status < 0) {
        VERBOSE_PROMPT("CONNECTION FAILED", stderr)
        fprintf(stdout, "CAN'T CONNECT\n");
        fflush(stdout);
        exit(EXIT_FAILURE);
    }

    VERBOSE_PROMPT("STARTING THREADS", stderr)

    pthread_t transmitter;
    thread_data transmitter_data;
    transmitter_data.file_descriptor = stdin;
    transmitter_data.socket_descriptor = socket_fd;

    pthread_create(&transmitter, NULL, transmitter_thread, &transmitter_data);

    pthread_t receiver;
    thread_data receiver_data;
    receiver_data.file_descriptor = stdout;
    receiver_data.socket_descriptor = socket_fd;

    pthread_create(&receiver, NULL, receiver_thread, &receiver_data);

    pthread_join(transmitter, NULL);
    pthread_join(receiver, NULL);
    // socket will be closed in thread functions

    shutdown(socket_fd, SHUT_RDWR);

    VERBOSE_PROMPT("\nCONNECTION CLOSED", stderr)
}

void *receiver_thread(void *arguments) {
    thread_data *data = (thread_data *) arguments;
    char buffer[BUFFER_SIZE + 1];
    memset(buffer, '\0', BUFFER_SIZE + 1);

    ssize_t bytes_read;
    while (1) {
        bytes_read = recv(data->socket_descriptor, buffer, BUFFER_SIZE, 0);
        if (bytes_read <= 0) break;
        buffer[bytes_read] = '\0';
        fprintf(data->file_descriptor, "%s", buffer);
        fflush(data->file_descriptor);
    }

    shutdown(data->socket_descriptor, SHUT_RD);               // stop socket reception
    int return_value = 0;
    pthread_exit(&return_value);
    return NULL;
}

void *transmitter_thread(void *arguments) {
    thread_data *data = (thread_data *) arguments;
    char buffer[BUFFER_SIZE + 1];
    size_t chunk_size;
    memset(buffer, '\0', BUFFER_SIZE + 1);
    while (1) {
        if (feof(data->file_descriptor)) {
            shutdown(data->socket_descriptor, SHUT_WR);       // stop socket transmission
            int return_value = 0;
            pthread_exit(&return_value);
            return NULL;
        }
//        chunk_size = fread(buffer, sizeof(char), BUFFER_SIZE, data->file_descriptor);
        chunk_size = read_line(buffer, BUFFER_SIZE, data->file_descriptor);
        send(data->socket_descriptor, buffer, chunk_size, 0);
    }

}

size_t read_line(char *buffer, size_t buffer_size, FILE *file_descriptor) {
    memset(buffer, '\0', buffer_size);
    char read_character;
    size_t chars_read = 0;
    do {
        read_character = (char) fgetc(file_descriptor);
        if (read_character == EOF) break;
        buffer[chars_read] = read_character;
        chars_read++;
    } while (read_character != '\n' && chars_read < buffer_size);
    buffer[chars_read] = '\0';
    return chars_read;
}

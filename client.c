#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define BUFFERLENGTH 256

/* displays error messages from system calls */
void error(char *msg)
{
    perror(msg);
    exit(0);
}

void create_message(char *args[], char *buf)
{
    switch (toupper(args[3][0]))
    {
    case 'A':
        sprintf(buf, "0 %s %s", args[4], args[5]);
        break;
    case 'C':
        sprintf(buf, "1 %s %s", args[4], args[5]);
        break;
    case 'D':
        sprintf(buf, "2 %s %s", args[4], args[5]);
        break;
    case 'L':
        sprintf(buf, "3");
        break;
    default:
        printf("Incorrect arguments");
        break;
    }
}

int main(int argc, char *argv[])
{
    int sockfd, n;
    struct addrinfo hints;
    struct addrinfo *result, *rp;
    int res;

    char buffer[BUFFERLENGTH];
    if (argc < 4)
    {
        fprintf(stderr, "usage %s hostname port command [command args]\n", argv[0]);
        exit(1);
    }

    /* Obtain address(es) matching host/port */
    /* code taken from the manual page for getaddrinfo */

    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = 0;
    hints.ai_protocol = 0;

    res = getaddrinfo(argv[1], argv[2], &hints, &result);
    if (res != 0)
    {
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(res));
        exit(EXIT_FAILURE);
    }

    /* getaddrinfo() returns a list of address structures.
       Try each address until we successfully connect(2).
       If socket(2) (or connect(2)) fails, we (close the socket
       and) try the next address. */

    for (rp = result; rp != NULL; rp = rp->ai_next)
    {
        sockfd = socket(rp->ai_family, rp->ai_socktype,
                        rp->ai_protocol);
        if (sockfd == -1)
            continue;

        if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) != -1)
            break;

        close(sockfd);
    }

    if (rp == NULL)
    {
        fprintf(stderr, "Could not connect\n");
        exit(EXIT_FAILURE);
    }

    freeaddrinfo(result);

    /* prepare message */
    bzero(buffer, BUFFERLENGTH);

    create_message(argv, buffer);
    printf("Sending %s\n", buffer);

    /* send message */
    n = write(sockfd, buffer, strlen(buffer));
    if (n < 0)
    {
        error("ERROR writing to socket");
    }
    bzero(buffer, BUFFERLENGTH);

    /* wait for reply */
    n = read(sockfd, buffer, BUFFERLENGTH - 1);
    if (n < 0)
    {
        error("ERROR reading from socket");
    }
    printf("%s\n", buffer);
    close(sockfd);
    return 0;
}

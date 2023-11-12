#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ctype.h>
#include <stdlib.h>
#include <strings.h>
#include <unistd.h>
#include <pthread.h>

#include "firewall.h"

#define BUFFERLENGTH 256

#define THREAD_IN_USE 0
#define THREAD_FINISHED 1
#define THREAD_AVAILABLE 2
#define THREADS_ALLOCATED 10

void parse_input(List *list, const char *str, char *output)
{
    Entry entry = empty_entry();

    switch (str[0])
    {
    case '0':
        if (!parse_entry(&entry, str + 2))
        {
            push(list, entry);
            sprintf(output, "Rule added");
        }
        else
        {
            sprintf(output, "Invalid rule");
        }

        break;
    case '1':
        if (parse_entry(&entry, str + 2))
        {
            if (is_valid(list, entry.address[0], entry.port[0]))
            {
                sprintf(output, "Connection accepted");
            }
            else
            {
                sprintf(output, "Connection rejected");
            }

            printf("Valid: %d\n", is_valid(list, entry.address[0], entry.port[0]));
        }
        else
        {
            sprintf(output, "Illegal IP address or port specified");
        }

        break;
    case '2':
        if (parse_entry(&entry, str + 2))
        {
            sprintf(output, "Rule invalid");
            break;
        }

        for (size_t i = 0; i < list->length; i++)
        {
            if (compare(&entry, nth(list, i)) == 0)
            {
                remove_list(list, i);
                sprintf(output, "Rule deleted");
                break;
            }
        }

        sprintf(output, "Rule not found");

        break;
    case '3':
        printf("Length: %zd\n", list->length);
        print_list(output, list);

        break;
    default:
        sprintf(output, "Illegal request");
        break;
    }
}

struct threadArgs_t
{
    int newsockfd;
    int threadIndex;
};

int isExecuted = 0;
List *list;
int returnValue = 0;                             /* not used; need something to keep compiler happy */
pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER; /* the lock used for processing */

/* this is only necessary for proper termination of threads - you should not need to access this part in your code */
struct threadInfo_t
{
    pthread_t pthreadInfo;
    pthread_attr_t attributes;
    int status;
};
struct threadInfo_t *serverThreads = NULL;
int noOfThreads = 0;
pthread_rwlock_t threadLock = PTHREAD_RWLOCK_INITIALIZER;
pthread_cond_t threadCond = PTHREAD_COND_INITIALIZER;
pthread_mutex_t threadEndLock = PTHREAD_MUTEX_INITIALIZER;

void error(char *message)
{
    perror(message);
    exit(1);
}

/* For each connection, this function is called in a separate thread. You need to modify this function. */
void *processRequest(void *args)
{
    struct threadArgs_t *threadArgs;
    char response[BUFFERLENGTH];
    char buffer[BUFFERLENGTH];
    int n;

    threadArgs = (struct threadArgs_t *)args;
    bzero(buffer, BUFFERLENGTH);
    n = read(threadArgs->newsockfd, buffer, BUFFERLENGTH - 1);
    if (n < 0)
    {
        error("ERROR reading from socket");
    }

    printf("Here is the message: %s\n", buffer);
    pthread_mutex_lock(&mut); /* lock exclusive access to variable isExecuted */
    isExecuted++;

    parse_input(list, buffer, response);

    pthread_mutex_unlock(&mut);
    /* send the reply back */
    n = write(threadArgs->newsockfd, buffer, BUFFERLENGTH);
    if (n < 0)
    {
        error("ERROR writing to socket");
    }

    serverThreads[threadArgs->threadIndex]
        .status = THREAD_FINISHED;
    pthread_cond_signal(&threadCond);

    close(threadArgs->newsockfd);
    free(threadArgs);
    pthread_exit(&returnValue);
}

/* finds unused thread info slot; allocates more slots if necessary
   only called by main thread */
int findThreadIndex()
{
    int i, tmp;

    for (i = 0; i < noOfThreads; i++)
    {
        if (serverThreads[i].status == THREAD_AVAILABLE)
        {
            serverThreads[i].status = THREAD_IN_USE;
            return i;
        }
    }

    // no available thread found; need to allocate more threads
    pthread_rwlock_wrlock(&threadLock);
    serverThreads = realloc(serverThreads, ((noOfThreads + THREADS_ALLOCATED) * sizeof(struct threadInfo_t)));
    noOfThreads = noOfThreads + THREADS_ALLOCATED;
    pthread_rwlock_unlock(&threadLock);
    if (serverThreads == NULL)
    {
        fprintf(stderr, "Memory allocation failed\n");
        exit(1);
    }
    // initialise thread status
    for (tmp = i + 1; tmp < noOfThreads; tmp++)
    {
        serverThreads[tmp].status = THREAD_AVAILABLE;
    }
    serverThreads[i].status = THREAD_IN_USE;
    return i;
}

/* waits for threads to finish and releases resources used by the thread management functions. You don't need to modify this function */
void *waitForThreads(void *args)
{
    int i, res;
    while (1)
    {
        pthread_mutex_lock(&threadEndLock);
        pthread_cond_wait(&threadCond, &threadEndLock);
        pthread_mutex_unlock(&threadEndLock);

        pthread_rwlock_rdlock(&threadLock);
        for (i = 0; i < noOfThreads; i++)
        {
            if (serverThreads[i].status == THREAD_FINISHED)
            {
                res = pthread_join(serverThreads[i].pthreadInfo, NULL);
                if (res != 0)
                {
                    fprintf(stderr, "thread joining failed, exiting\n");
                    exit(1);
                }
                serverThreads[i].status = THREAD_AVAILABLE;
            }
        }
        pthread_rwlock_unlock(&threadLock);
    }
}

int main(int argc, char *argv[])
{
    socklen_t clilen;
    int sockfd, portno;
    struct sockaddr_in6 serv_addr, cli_addr;
    int result;
    pthread_t waitInfo;
    pthread_attr_t waitAttributes;

    if (argc < 2)
    {
        fprintf(stderr, "ERROR, no port provided\n");
        exit(1);
    }

    pthread_mutex_lock(&mut);

    list = malloc(sizeof(List));
    *list = empty_list();

    pthread_mutex_unlock(&mut);

    /* create socket */
    sockfd = socket(AF_INET6, SOCK_STREAM, 0);
    if (sockfd < 0)
        error("ERROR opening socket");
    bzero((char *)&serv_addr, sizeof(serv_addr));
    portno = atoi(argv[1]);
    serv_addr.sin6_family = AF_INET6;
    serv_addr.sin6_addr = in6addr_any;
    serv_addr.sin6_port = htons(portno);

    /* bind it */
    if (bind(sockfd, (struct sockaddr *)&serv_addr,
             sizeof(serv_addr)) < 0)
    {
        error("ERROR on binding");
    }

    printf("Waiting for connections\n");

    /* ready to accept connections */
    listen(sockfd, 5);
    clilen = sizeof(cli_addr);

    /* create separate thread for waiting  for other threads to finish */
    if (pthread_attr_init(&waitAttributes))
    {
        fprintf(stderr, "Creating initial thread attributes failed!\n");
        exit(1);
    }

    result = pthread_create(&waitInfo, &waitAttributes, waitForThreads, NULL);
    if (result != 0)
    {
        fprintf(stderr, "Initial Thread creation failed!\n");
        exit(1);
    }

    /* now wait in an endless loop for connections and process them */
    while (1)
    {

        struct threadArgs_t *threadArgs; /* must be allocated on the heap to prevent variable going out of scope */
        int threadIndex;

        threadArgs = malloc(sizeof(struct threadArgs_t));
        if (!threadArgs)
        {
            fprintf(stderr, "Memory allocation failed!\n");
            exit(1);
        }

        /* waiting for connections */
        threadArgs->newsockfd = accept(sockfd,
                                       (struct sockaddr *)&cli_addr,
                                       &clilen);
        if (threadArgs->newsockfd < 0)
        {
            error("ERROR on accept");
        }

        /* create thread for processing of connection */
        threadIndex = findThreadIndex();
        threadArgs->threadIndex = threadIndex;
        if (pthread_attr_init(&(serverThreads[threadIndex].attributes)))
        {
            fprintf(stderr, "Creating thread attributes failed!\n");
            exit(1);
        }

        result = pthread_create(&(serverThreads[threadIndex].pthreadInfo), &(serverThreads[threadIndex].attributes), processRequest, (void *)threadArgs);
        if (result != 0)
        {
            fprintf(stderr, "Thread creation failed!\n");
            exit(1);
        }
    }
}

/*int main()
{
    pthread_mutex_lock(&mut);

    list = malloc(sizeof(List));
    *list = empty_list();

    // pthread_mutex_unlock(&mut);

    parse_input(list, "0 129.112.67.3 67-123");
    parse_input(list, "0 65.246.1.56-78.12.0.5 16");
    parse_input(list, "0 0.1.2.3 456-789");
    parse_input(list, "0 234.0.0.5 6554-1992");
    parse_input(list, "0 111.222.222.222-223.224.225.226 2147483645-2147483646");
    parse_input(list, "0 125.64.0.1 54-123");

    parse_input(list, "1 125.64.0.1 56");

    parse_input(list, "3");

    // pthread_mutex_lock(&mut);

    free_list(list);

    pthread_mutex_unlock(&mut);

    return 0;
}*/

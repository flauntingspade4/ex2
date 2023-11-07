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

void parse_input(List *list, const char *str)
{
    Entry entry = empty_entry();

    switch (str[0])
    {
    case '0':
        parse_entry(&entry, str + 2);

        // print_entry(&entry);

        push(list, entry);
        break;
    case '1':
        parse_entry(&entry, str + 2);

        // print_entry(&entry);

        printf("Valid: %d\n", is_valid(list, entry.address[0], entry.port[0]));
        break;
    case '2':
        parse_entry(&entry, str + 2);

        // print_entry(&entry);

        for (size_t i = 0; i < list->length; i++)
        {
            if (compare(&entry, nth(list, i)) == 0)
            {
                remove_list(list, i);
                break;
            }
        }
        break;
    case '3':
        printf("Length: %zd\n", list->length);
        print_list(list);
        break;
    default:
        printf("Whoops\n");
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

    parse_input(list, buffer);

    sprintf(buffer, "I got you message, the  value of isExecuted is %d\n", isExecuted);
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

int main()
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
}

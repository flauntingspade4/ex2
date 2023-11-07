#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "firewall.h"

List empty_list()
{
    List list;

    memset((void *)&list, 0, sizeof(List));

    return list;
}

Entry empty_entry()
{
    Entry entry;

    memset((void *)&entry, 0, sizeof(Entry));

    return entry;
}

void _reallocate(List *list)
{

    printf("Before realloc %p %d\n", list->array, sizeof(Entry) * list->capacity);
    print_list(list);
    list->capacity = list->capacity * 2 + 3;

    list->array = realloc((void *)list->array, sizeof(Entry) * list->capacity);

    printf("After realloc %p %d\n", list->array, sizeof(Entry) * list->capacity);
    print_list(list);

    if (!list->array)
    {
        perror("List malloc failed");
        exit(1);
    }
}

int length(const List *list)
{
    return list->length;
}

void push(List *list, Entry entry)
{
    if (list->length >= list->capacity)
    {
        _reallocate(list);
    }

    *(list->array + sizeof(Entry) * list->length) = entry;

    list->length += 1;
}

void remove_list(List *list, size_t n)
{
    memmove(nth(list, n), nth(list, list->length - 1), sizeof(Entry));

    list->length -= 1;
}

Entry *nth(List *list, size_t n)
{
    if (n >= list->length)
    {
        return NULL;
    }

    return list->array + sizeof(Entry) * n;
}

void push_matched(MatchedQueries **matched, unsigned char address[4], unsigned int port)
{
    if (!(*matched))
    {
        struct MatchedQueries new_matched;
        memcpy(new_matched.address, address, sizeof(new_matched.address));
        new_matched.port = port;
        new_matched.next = NULL;

        printf("Here\n");

        *matched = malloc(sizeof(MatchedQueries));

        if (!(*matched))
        {
            perror("Matched malloc failed");
            exit(1);
        }

        **matched = new_matched;
    }
    else
    {
        push_matched((&(*matched)->next), address, port);
    }
}

void free_matched(MatchedQueries *matched)
{
    if (matched)
    {
        free_matched(matched->next);

        free(matched->next);
    }
}

void free_list(List *list)
{
    free(list->array);

    for (int i = 0; i < list->length; i++)
    {
        Entry *entry = list->array + i * sizeof(Entry);

        free_matched(entry->matched);
    }
}

void print_matched(MatchedQueries *matched)
{
    printf("Printing matched %p\n", matched);

    if (matched)
    {
        printf("Query: %d.%d.%d.%d %d\n", matched->address[0], matched->address[1], matched->address[2], matched->address[3], matched->port);

        print_matched(matched->next);
    }
}

void print_list(const List *list)
{
    printf("Printing all\n");

    for (int i = 0; i < list->length; i++)
    {
        // printf("Doing %d\n", i);
        print_entry(nth(list, i));
    }
}

void print_entry(const Entry *entry)
{
    printf("Rule: ");

    if (memcmp(entry->address[1], (int[]){0, 0, 0, 0}, sizeof(entry->address[1])) == 0)
    {
        if (entry->port[1] == 0)
        {
            printf("%d.%d.%d.%d %d\n", entry->address[0][0], entry->address[0][1], entry->address[0][2], entry->address[0][3], entry->port[0]);
        }
        else
        {
            printf("%d.%d.%d.%d %d-%d\n", entry->address[0][0], entry->address[0][1], entry->address[0][2], entry->address[0][3], entry->port[0], entry->port[1]);
        }
    }
    else
    {
        if (entry->port[1] == 0)
        {
            printf("%d.%d.%d.%d-%d.%d.%d.%d %d\n", entry->address[0][0], entry->address[0][1], entry->address[0][2], entry->address[0][3], entry->address[1][0], entry->address[1][1], entry->address[1][2], entry->address[1][3], entry->port[0]);
        }
        else
        {
            printf("%d.%d.%d.%d-%d.%d.%d.%d %d-%d\n", entry->address[0][0], entry->address[0][1], entry->address[0][2], entry->address[0][3], entry->address[1][0], entry->address[1][1], entry->address[1][2], entry->address[1][3], entry->port[0], entry->port[1]);
        }
    }

    print_matched(entry->matched);

    printf("Printed matched\n");
}

int parse_address(const char *str, unsigned char addresses[2][4], int len)
{
    int address_index = 0;
    int part_index = 0;

    int start_index = 0;

    for (int i = 0; i <= len; i++)
    {
        char current = str[i];

        if (current < '0' || current > '9')
        {
            char container[5] = {0};

            strncpy(container, str + start_index, i - start_index);

            int part = atoi(container);

            addresses[address_index][part_index] = part;

            start_index = i + 1;

            part_index += (int)current == '.';

            if (current == '-')
            {
                address_index++;
                part_index = 0;
            }
        }
    }

    return 0;
}

int parse_port(const char *str, int ports[2])
{
    int len = strlen(str);

    int port_index = 0;

    int start_index = 0;

    for (int i = 0; i <= len; i++)
    {
        char current = str[i];

        if (current < '0' || current > '9')
        {
            char container[15] = {0};

            strncpy(container, str + start_index, i - start_index);

            int port = atoi(container);

            ports[port_index] = port;

            start_index = i + 1;
            port_index++;
        }
    }

    return 0;
}

int parse_entry(Entry *entry, const char *str)
{
    char *pos = strstr(str, " ");

    if (pos)
    {
        int addr_res = parse_address(str, entry->address, pos - str);

        if (addr_res != 0)
        {
            return addr_res;
        }

        return parse_port(pos + 1, entry->port);
    }
    else
    {
        return 1;
    }
}

int port_valid(Entry *entry, unsigned char address[4], unsigned int port)
{
    if (entry->port[0] == port)
    {
        push_matched(&(entry->matched), address, port);

        return 1;
    }

    if (entry->port[1] != 0 && (entry->port[0] <= port && port >= entry->port[1]))
    {
        push_matched(&(entry->matched), address, port);

        return 1;
    }

    return 0;
}

int is_valid(List *list, unsigned char address[4], unsigned int port)
{
    for (int i = 0; i < list->length; i++)
    {
        Entry *entry = list->array + i * sizeof(Entry);

        if (memcmp(entry->address[0], address, sizeof(entry->address[0])) == 0)
        {
            return port_valid(entry, address, port);
        }

        if (memcmp(entry->address[1], (int[]){0, 0, 0, 0}, sizeof(entry->address[1])) != 0)
        {
            for (int j = 0; j < 4; j++)
            {
                if (address[j] < entry->address[0][j] || address[j] > entry->address[1][j])
                {
                    return 0;
                }
            }

            return port_valid(entry, address, port);
        }
    }

    return 0;
}

int compare(const Entry *lhs, const Entry *rhs)
{
    for (int i = 0; i < 4; i++)
    {
        if (lhs->address[0][i] > rhs->address[0][i])
        {
            return 1;
        }
        else if (lhs->address[0][i] < rhs->address[0][i])
        {
            return -1;
        }
    }

    if (lhs->port[0] > rhs->port[0])
    {
        return 1;
    }
    else if (lhs->port[0] == rhs->port[0])
    {
        return 0;
    }
    else
    {
        return -1;
    }
}

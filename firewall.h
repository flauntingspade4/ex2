#include <stdlib.h>

typedef struct List
{
    struct Entry *array;
    size_t length;
    size_t capacity;
} List;

List empty_list();

typedef struct MatchedQueries
{
    unsigned char address[4];
    unsigned int port;
    struct MatchedQueries *next;
} MatchedQueries;

typedef struct Entry
{
    unsigned char address[2][4];
    unsigned int port[2];
    struct MatchedQueries *matched;
} Entry;

void print_list(char *, const List *);
void print_entry(char *, const Entry *);
Entry empty_entry();
int compare(const Entry *lhs, const Entry *rhs);

int length(const List *);
void push(List *, Entry);
void remove_list(List *, size_t);
Entry *nth(List *, size_t);
void free_list(List *);

int is_valid(List *, unsigned char address[4], unsigned int port);

int parse_entry(Entry *entry, const char *str);

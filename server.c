#include <stdlib.h>
#include <stdio.h>

#include "firewall.h"

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

        print_entry(&entry);

        is_valid(list, entry.address[0], entry.port[0]);
        break;
    case '2':
        parse_entry(&entry, str + 2);

        print_entry(&entry);

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
        printf("Length: %d\n", list->length);
        print_list(list);
        break;
    default:
        printf("Whoops\n");
    }
}

int main()
{
    List list = empty_list();

    parse_input(&list, "0 129.112.67.3 67-123");
    parse_input(&list, "0 65.246.1.56-78.12.0.5 16");
    parse_input(&list, "0 0.1.2.3 456-789");
    parse_input(&list, "0 234.0.0.5 6554-1992");
    parse_input(&list, "0 111.222.222.222-223.224.225.226 2147483645-2147483646");
    parse_input(&list, "0 125.64.0.1 54-123");

    parse_input(&list, "1 125.64.0.1 56");

    parse_input(&list, "3");

    free_list(&list);

    return 0;
}

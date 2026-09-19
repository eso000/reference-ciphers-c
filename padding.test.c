#include "padding.h"

#include <stdio.h>
#include <stdlib.h>


int main()
{
    uint8_t *v = (uint8_t *) malloc(3);

    *v = 17;
    *(v+1) = 17;
    *(v+2) = 17;

    //padZeros(v, 3, 3);
    //padPKCS(v,3,3);
    //padANSIX923(v,3,3);
    padISO78164(v,3,3);
    for(uint8_t *i= v; i<v+6; ++i)
        printf("%.2x,", *i);
    printf("\n");
}

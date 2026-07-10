/* primes.exe — a little CPU work: sieve of Eratosthenes on the OS heap. */
#include "alpha.h"

#define LIMIT 10000

int app_main(const alpha_api_t *os)
{
    unsigned char *sieve = os->alloc(LIMIT + 1);
    if (!sieve) {
        os->print("out of memory\n");
        return 1;
    }
    for (int i = 0; i <= LIMIT; i++)
        sieve[i] = 1;
    sieve[0] = sieve[1] = 0;
    for (int i = 2; i * i <= LIMIT; i++)
        if (sieve[i])
            for (int j = i * i; j <= LIMIT; j += i)
                sieve[j] = 0;

    int count = 0, largest = 0;
    for (int i = 2; i <= LIMIT; i++)
        if (sieve[i]) {
            count++;
            largest = i;
        }

    aprintf(os, "primes below %u: %d (largest: %d)\n", LIMIT, count, largest);
    os->print("last ten: ");
    int shown = 0;
    for (int i = LIMIT; i >= 2 && shown < 10; i--)
        if (sieve[i]) {
            aprintf(os, "%d ", i);
            shown++;
        }
    os->putchar('\n');

    os->free(sieve);
    return 0;
}

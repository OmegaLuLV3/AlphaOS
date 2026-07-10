/* sysinfo.exe — show what the kernel knows about the machine. */
#include "alpha.h"

int app_main(const alpha_api_t *os)
{
    alpha_meminfo_t mi;
    os->meminfo(&mi);

    unsigned int ms = os->uptime_ms();

    os->set_color(ALPHA_LCYAN, ALPHA_BLACK);
    os->print("AlphaOS system information\n");
    os->set_color(ALPHA_LGREY, ALPHA_BLACK);
    aprintf(os, "  uptime      %u.%us\n", ms / 1000, (ms % 1000) / 100);
    aprintf(os, "  RAM total   %u KiB\n", mi.total_kib);
    aprintf(os, "  RAM free    %u KiB\n", mi.free_kib);
    aprintf(os, "  RAM used    %u KiB\n", mi.total_kib - mi.free_kib);
    aprintf(os, "  kheap used  %u bytes\n", mi.heap_used);
    aprintf(os, "  kheap free  %u bytes\n", mi.heap_free);
    return 0;
}

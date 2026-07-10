/* hello.exe — the canonical first program. */
#include "alpha.h"

int app_main(const alpha_api_t *os)
{
    os->set_color(ALPHA_YELLOW, ALPHA_BLACK);
    os->print("Hello from hello.exe!\n");
    os->set_color(ALPHA_LGREY, ALPHA_BLACK);
    aprintf(os, "I am a PE32 executable loaded by AlphaOS (API v%u).\n",
            os->version);
    return 0;
}

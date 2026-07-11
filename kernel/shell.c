/* The AlphaOS command shell. */
#include "kernel.h"

#define LINE_MAX 128

static void cmd_help(void)
{
    kprint("commands:\n"
           "  ls              list files on the ramdisk\n"
           "  run <file.exe>  load and execute a PE executable\n"
           "  peinfo <file>   show PE headers of an executable\n"
           "  mem             physical memory and heap statistics\n"
           "  lspci           list devices on the PCI bus\n"
           "  date            read the real-time clock\n"
           "  ping            ping the network gateway (needs a NIC)\n"
           "  nslookup <name> resolve a hostname via DNS (needs a NIC)\n"
           "  http <host> [path]  fetch a page over plain HTTP\n"
           "  ai <question>   ask the AI assistant (needs ai_bridge.py)\n"
           "  uptime          time since boot\n"
           "  clear           clear the screen\n"
           "  echo <text>     print text\n"
           "  help            this text\n"
           "  halt            power off\n"
           "typing a bare name ending in .exe also runs it\n");
}

static void cmd_ls(void)
{
    u32 n = ramdisk_count();
    if (!n) {
        kprint("(ramdisk empty)\n");
        return;
    }
    for (u32 i = 0; i < n; i++) {
        rd_file_t *f = ramdisk_get(i);
        kprintf("  %6u  %s\n", f->size, f->name);
    }
}

static void cmd_mem(void)
{
    u32 total = pmm_total_kib(), free_k = pmm_free_kib();
    u32 hu, hf;
    kheap_stats(&hu, &hf);
    kprintf("physical: %u KiB total, %u KiB used, %u KiB free\n",
            total, total - free_k, free_k);
    kprintf("kheap:    %u bytes used, %u bytes free\n", hu, hf);
}

static void cmd_lspci(void)
{
    for (u32 i = 0; i < pci_count(); i++) {
        pci_dev_t *d = pci_get(i);
        kprintf("  %02x:%02x.%d  %04x:%04x  %s\n",
                d->bus, d->slot, d->func, d->vendor, d->device, d->name);
    }
}

static void cmd_date(void)
{
    rtc_time_t t;
    rtc_read(&t);
    kprintf("%02d/%02d/%d %02d:%02d:%02d UTC\n",
            t.day, t.month, t.year, t.hour, t.min, t.sec);
}

static void cmd_uptime(void)
{
    u32 ms = uptime_ms();
    kprintf("up %u.%02us (%u ticks)\n", ms / 1000, (ms % 1000) / 10,
            pit_ticks());
}

static void cmd_ping(void)
{
    if (!net_ready()) {
        kprint("ping: no NIC (boot with -netdev user,id=net0 "
               "-device rtl8139,netdev=net0)\n");
        return;
    }
    const u8 *ip = net_gateway_ip();
    kprintf("pinging gateway %u.%u.%u.%u...\n", ip[0], ip[1], ip[2], ip[3]);
    u32 rtt;
    if (net_ping(ip, &rtt))
        kprintf("reply from %u.%u.%u.%u: time=%ums\n", ip[0], ip[1], ip[2],
                ip[3], rtt);
    else
        kprint("ping: no reply (timed out)\n");
}

static void cmd_nslookup(const char *hostname)
{
    if (!net_ready()) {
        kprint("nslookup: no NIC (boot with -netdev user,id=net0 "
               "-device rtl8139,netdev=net0)\n");
        return;
    }
    if (!*hostname) {
        kprint("usage: nslookup <hostname>\n");
        return;
    }
    u8 ip[4];
    if (net_dns_resolve(hostname, ip))
        kprintf("%s -> %u.%u.%u.%u\n", hostname, ip[0], ip[1], ip[2], ip[3]);
    else
        kprintf("nslookup: %s: no answer (timed out or NXDOMAIN)\n", hostname);
}

static void cmd_http(char *arg)
{
    if (!net_ready()) {
        kprint("http: no NIC (boot with -netdev user,id=net0 "
               "-device rtl8139,netdev=net0)\n");
        return;
    }
    char *host = arg;
    char *path = arg;
    while (*path && *path != ' ')
        path++;
    if (*path)
        *path++ = 0;
    while (*path == ' ')
        path++;
    if (!*host) {
        kprint("usage: http <host> [path]  (plain HTTP/80 only -- no TLS yet)\n");
        return;
    }

    static u8 resp[4096];
    kprintf("GET http://%s%s ...\n", host, *path ? path : "/");
    u32 n = net_http_get(host, path, resp, sizeof(resp) - 1);
    if (!n) {
        kprint("http: request failed (DNS, connect, or empty response)\n");
        return;
    }
    resp[n] = 0;
    kprintf("--- %u bytes ---\n", n);
    kprint((const char *)resp);
    kprint("\n--- end ---\n");
}

static void cmd_run(const char *cmdline)
{
    if (!*cmdline) {
        kprint("usage: run <file.exe> [args]\n");
        return;
    }
    /* first word is the executable; the whole string becomes the
       process command line (GetCommandLineA) */
    char name[64];
    u32 i = 0;
    while (cmdline[i] && cmdline[i] != ' ' && i < sizeof(name) - 1) {
        name[i] = cmdline[i];
        i++;
    }
    name[i] = 0;

    rd_file_t *f = ramdisk_find(name);
    if (!f) {
        kprintf("run: %s: not found (try 'ls')\n", name);
        return;
    }
    u32 t0 = uptime_ms();
    int code = pe_run(f, cmdline);
    kprintf("[os] %s exited with code %d (%u ms)\n",
            name, code, uptime_ms() - t0);
}

static bool ends_with_exe(const char *s)
{
    usize n = strlen(s);
    return n > 4 && strcmp(s + n - 4, ".exe") == 0;
}

static void halt_machine(void)
{
    kprint("powering off...\n");
    /* qemu/bochs poweroff ports; fall back to halt loop on real HW */
    outb(0x604, 0x00);
    outb(0xB004, 0x00);
    __asm__ volatile("outw %0, %1" : : "a"((u16)0x2000), "Nd"((u16)0x604));
    cli();
    for (;;)
        hlt();
}

void shell_run(void)
{
    char line[LINE_MAX];

    for (;;) {
        console_set_color(ALPHA_LGREEN, ALPHA_BLACK);
        kprint("alpha> ");
        console_set_color(ALPHA_LGREY, ALPHA_BLACK);
        input_readline(line, LINE_MAX);

        /* split command word / argument */
        char *arg = line;
        while (*arg && *arg != ' ')
            arg++;
        if (*arg)
            *arg++ = 0;
        while (*arg == ' ')
            arg++;

        if (!line[0])
            continue;
        else if (strcmp(line, "help") == 0)
            cmd_help();
        else if (strcmp(line, "ls") == 0)
            cmd_ls();
        else if (strcmp(line, "mem") == 0)
            cmd_mem();
        else if (strcmp(line, "uptime") == 0)
            cmd_uptime();
        else if (strcmp(line, "lspci") == 0)
            cmd_lspci();
        else if (strcmp(line, "date") == 0)
            cmd_date();
        else if (strcmp(line, "ping") == 0)
            cmd_ping();
        else if (strcmp(line, "nslookup") == 0)
            cmd_nslookup(arg);
        else if (strcmp(line, "http") == 0)
            cmd_http(arg);
        else if (strcmp(line, "ai") == 0) {
            if (*arg)
                ai_ask(arg);
            else
                kprint("usage: ai <question>\n");
        }
        else if (strcmp(line, "clear") == 0)
            console_clear();
        else if (strcmp(line, "echo") == 0)
            kprintf("%s\n", arg);
        else if (strcmp(line, "run") == 0)
            cmd_run(arg);
        else if (strcmp(line, "peinfo") == 0) {
            rd_file_t *f = ramdisk_find(arg);
            if (f)
                pe_info(f);
            else
                kprintf("peinfo: %s: not found\n", arg);
        }
        else if (strcmp(line, "halt") == 0 || strcmp(line, "poweroff") == 0)
            halt_machine();
        else if (ends_with_exe(line))
            cmd_run(line);
        else
            kprintf("%s: unknown command (try 'help')\n", line);
    }
}

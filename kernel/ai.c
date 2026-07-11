/*
 * AI assistant channel: a deliberately tiny, allowlisted bridge between
 * the `ai` shell command and a host-side process (tools/ai_bridge.py)
 * that holds real network access and an Anthropic API key.
 *
 * AlphaOS has no network/TLS stack — a live Claude API call cannot
 * originate inside this kernel, and building one from scratch is its
 * own project. Rather than fake that, the split is explicit: this
 * driver talks a small text protocol over COM2 to a host process,
 * which does the actual model call and tool-use loop.
 *
 * The safety boundary lives here, on the guest side, and is structural
 * rather than promised: do_tool() below is a closed switch over five
 * names. There is no "write file", "delete", "format", "shutdown", or
 * "run arbitrary code" opcode anywhere in this protocol — those code
 * paths simply do not exist, so no prompt, no host-side bug, and no
 * malicious response from a compromised bridge can reach them. The
 * ramdisk itself is read-only at runtime (see ramdisk.c), so even
 * "run_exe" can only execute a binary that was already baked into the
 * OS image at build time; nothing new can be introduced at runtime.
 * The host bridge adds its own layer on top (run_exe gated behind
 * --allow-run plus an interactive human confirmation, turn limits,
 * logging) — see tools/ai_bridge.py.
 */
#include "kernel.h"

#define COM2 0x2F8
#define AI_LINE_MAX   256
#define AI_CAP_MAX    2048
#define AI_TIMEOUT_MS 60000   /* generous: a real API round trip is slow */
#define AI_MAX_TOOL_CALLS 12  /* guest-side backstop against a runaway loop */

static void com2_putc(char c)
{
    while (!(inb(COM2 + 5) & 0x20))
        ;
    outb(COM2, c);
}

static void com2_puts(const char *s)
{
    while (*s)
        com2_putc(*s++);
}

static int com2_getc(void)
{
    if (!(inb(COM2 + 5) & 0x01))
        return -1;
    return inb(COM2);
}

void ai_init(void)
{
    outb(COM2 + 1, 0x00);
    outb(COM2 + 3, 0x80);
    outb(COM2 + 0, 0x01); /* divisor 1 -> 115200 baud */
    outb(COM2 + 1, 0x00);
    outb(COM2 + 3, 0x03);
    outb(COM2 + 2, 0xC7);
    outb(COM2 + 4, 0x0B);
    kprint("ai: assistant channel ready on COM2 "
           "(needs tools/ai_bridge.py on the host)\n");
}

/* Blocking line read with an idle timeout, measured via the PIT tick
   count (100 Hz -> 10 ms/tick). Returns false if nothing arrives in
   time, which is exactly what happens if no bridge is attached — the
   `ai` command must fail gracefully, not hang the shell forever. */
static bool com2_readline(char *buf, u32 max, u32 timeout_ms)
{
    u32 len = 0;
    u32 timeout_ticks = timeout_ms / 10;
    u32 last = pit_ticks();

    for (;;) {
        int c = com2_getc();
        if (c < 0) {
            if (pit_ticks() - last > timeout_ticks)
                return false;
            sti();
            hlt();
            continue;
        }
        last = pit_ticks();
        if (c == '\r')
            continue;
        if (c == '\n') {
            buf[len] = 0;
            return true;
        }
        if (len + 1 < max)
            buf[len++] = (char)c;
    }
}

/* Send a (possibly multi-line, possibly empty) buffer as a run of
   "<prefix><line>\n" frames. */
static void send_lines(const char *prefix, const char *text)
{
    if (!*text) {
        com2_puts(prefix);
        com2_puts("(no output)\n");
        return;
    }
    const char *p = text;
    while (*p) {
        const char *nl = p;
        while (*nl && *nl != '\n')
            nl++;
        com2_puts(prefix);
        for (const char *q = p; q < nl; q++)
            com2_putc(*q);
        com2_putc('\n');
        p = (*nl) ? nl + 1 : nl;
    }
}

/*
 * The entire allowlist. Every operation here is either strictly
 * read-only (list_files, read_pe_info, mem_stats, pci_list) or bounded
 * by facts already true of this OS (run_exe can only launch a binary
 * that shipped in the read-only ramdisk — it cannot introduce new code).
 * Fault isolation (see pe.c/idt.c) still applies: a crashing run_exe
 * only kills that one process.
 */
static char capbuf[AI_CAP_MAX];

static void do_tool(char *req)
{
    char *sp = strchr(req, ' ');
    const char *arg = "";
    if (sp) {
        *sp = 0;
        arg = sp + 1;
    }
    const char *name = req;

    console_capture_start(capbuf, sizeof(capbuf));

    if (strcmp(name, "list_files") == 0) {
        for (u32 i = 0; i < ramdisk_count(); i++) {
            rd_file_t *f = ramdisk_get(i);
            kprintf("%6u  %s\n", f->size, f->name);
        }
    } else if (strcmp(name, "read_pe_info") == 0) {
        rd_file_t *f = ramdisk_find(arg);
        if (f)
            pe_info(f);
        else
            kprintf("not found: %s\n", arg);
    } else if (strcmp(name, "mem_stats") == 0) {
        u32 total = pmm_total_kib(), free_k = pmm_free_kib();
        u32 hu, hf;
        kheap_stats(&hu, &hf);
        kprintf("physical: %u KiB total, %u KiB used, %u KiB free\n",
                total, total - free_k, free_k);
        kprintf("kheap: %u bytes used, %u bytes free\n", hu, hf);
        kprintf("uptime: %u ms\n", uptime_ms());
    } else if (strcmp(name, "pci_list") == 0) {
        for (u32 i = 0; i < pci_count(); i++) {
            pci_dev_t *d = pci_get(i);
            kprintf("%02x:%02x.%d  %04x:%04x  %s\n", d->bus, d->slot,
                    d->func, d->vendor, d->device, d->name);
        }
    } else if (strcmp(name, "run_exe") == 0) {
        rd_file_t *f = ramdisk_find(arg);
        if (f) {
            int code = pe_run(f, arg);
            kprintf("%s exited with code %d\n", arg, code);
        } else {
            kprintf("not found: %s\n", arg);
        }
    } else {
        kprintf("error: '%s' is not an allowlisted tool\n", name);
    }

    console_capture_stop();
    send_lines("RESULT: ", capbuf);
    com2_puts("RESULT_END\n");
}

void ai_ask(const char *question)
{
    char line[AI_LINE_MAX];
    u32 tool_calls = 0;

    com2_puts("ASK: ");
    com2_puts(question);
    com2_putc('\n');

    for (;;) {
        if (!com2_readline(line, sizeof(line), AI_TIMEOUT_MS)) {
            kprint("[ai] no response (is tools/ai_bridge.py running and "
                   "attached to this VM's COM2?)\n");
            return;
        }

        if (strncmp(line, "SAY: ", 5) == 0) {
            kprint(line + 5);
            kputc('\n');
        } else if (strcmp(line, "SAY_END") == 0) {
            /* delimiter only */
        } else if (strncmp(line, "TOOL: ", 6) == 0) {
            if (++tool_calls > AI_MAX_TOOL_CALLS) {
                kprint("[ai] too many tool calls in one turn, aborting\n");
                com2_puts("RESULT: (guest aborted: tool call limit)\n");
                com2_puts("RESULT_END\n");
                return;
            }
            do_tool(line + 6);
        } else if (strcmp(line, "DONE") == 0) {
            return;
        }
        /* any other line: ignore, forward-compatible */
    }
}

/* watchdog.c — Independent watchdog daemon for guardian self-protection.
 *
 * Monitors /run/guardian/guardian.pid and /run/guardian/guardian.heartbeat.
 * If the daemon dies or halts for more than 5 seconds, it activates the
 * network kill switch by deleting the default route via ioctl (no system()
 * shell calls).
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>
#include <time.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/route.h>
#include <netinet/in.h>

static int trigger_kill_switch(void) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return -errno;
    struct rtentry rt;
    memset(&rt, 0, sizeof(rt));
    rt.rt_dst.sa_family = AF_INET;
    ((struct sockaddr_in*)&rt.rt_dst)->sin_addr.s_addr = INADDR_ANY;
    rt.rt_gateway.sa_family = AF_INET;
    ((struct sockaddr_in*)&rt.rt_gateway)->sin_addr.s_addr = INADDR_ANY;
    rt.rt_genmask.sa_family = AF_INET;
    ((struct sockaddr_in*)&rt.rt_genmask)->sin_addr.s_addr = INADDR_ANY;
    rt.rt_flags = RTF_UP | RTF_GATEWAY;
    int rc = ioctl(sock, SIOCDELRT, &rt);
    int saved = errno;
    close(sock);
    if (rc != 0 && saved != ESRCH) {
        return -saved;
    }
    printf("[watchdog] KILL SWITCH ACTIVATED — default route deleted\n");
    return 0;
}

int main(void) {
    /* Vuln 1: block debugging/ptrace injection on the watchdog itself */
    prctl(PR_SET_DUMPABLE, 0);
    printf("[watchdog] started. Monitoring guardian heartbeat...\n");

    while (1) {
        sleep(1);

        /* 1. Read PID */
        FILE *pf = fopen("/run/guardian/guardian.pid", "r");
        if (!pf) {
            /* Daemon has not written its PID yet, or is starting/restarting */
            continue;
        }
        int pid = 0;
        if (fscanf(pf, "%d", &pid) != 1 || pid <= 0) {
            fclose(pf);
            continue;
        }
        fclose(pf);

        /* 2. Check process liveness */
        if (kill(pid, 0) != 0) {
            printf("[watchdog] Guardian daemon process (PID %d) is dead! Activating kill switch...\n", pid);
            trigger_kill_switch();
            break;
        }

        /* 3. Check heartbeat timestamp */
        FILE *hb = fopen("/run/guardian/guardian.heartbeat", "r");
        if (!hb) {
            /* heartbeat file missing temporarily or not created yet */
            continue;
        }
        long hb_ts = 0;
        if (fscanf(hb, "%ld", &hb_ts) != 1) {
            fclose(hb);
            continue;
        }
        fclose(hb);

        struct timespec ts;
        clock_gettime(CLOCK_MONOTONIC, &ts);
        long now = (long)ts.tv_sec;
        if (now - hb_ts > 5) {
            printf("[watchdog] Guardian heartbeat timeout! Last updated %ld seconds ago. Activating kill switch...\n", now - hb_ts);
            trigger_kill_switch();
            break;
        }
    }
    return 0;
}

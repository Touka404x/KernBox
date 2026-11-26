#define _GNU_SOURCE

#include "broker_core.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#define BROKER_STR_HELPER(x) #x
#define BROKER_STR(x) BROKER_STR_HELPER(x)
#define BROKER_LINE_TOO_LONG_MSG "line exceeds " BROKER_STR(BROKER_MAX_RPC_LINE_BYTES) " bytes"

static void log_stderr(const char *msg) {
    if (!msg) return;
    size_t len = strlen(msg);
    if (len > 0) {
        ssize_t w = write(STDERR_FILENO, msg, len);
        (void)w;
    }
    ssize_t nl = write(STDERR_FILENO, "\n", 1);
    (void)nl;
}

#define MAX_CONNS 8
#define MAX_EPOLL_EVENTS 16

typedef enum conn_state {
    ST_FREE = 0,
    ST_READ_CLIENT,
    ST_CONNECT_GUARD,
    ST_WRITE_GUARD,
    ST_READ_GUARD,
    ST_WRITE_CLIENT
} conn_state_t;

typedef struct conn_slot {
    int client_fd;
    int guard_fd;
    conn_state_t state;
    uint64_t deadline_ms;
    size_t req_len;
    size_t req_sent;
    size_t resp_len;
    size_t resp_sent;
    int is_install_apk;
    char req_id[BROKER_MAX_ID_BYTES + 1];
    char req_buf[BROKER_MAX_RPC_LINE_BYTES + 2];
    char resp_buf[BROKER_MAX_RPC_RESP_BYTES + 2];
} conn_slot_t;

static conn_slot_t g_slots[MAX_CONNS];
static int g_epfd = -1;

static uint64_t monotonic_ms(void) {
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0;
    }
    return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)(ts.tv_nsec / 1000000L);
}

static int read_small_nofollow(const char *path, char *buf, size_t cap, size_t *out_len, int require_root) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }
    if (require_root && st.st_uid != 0) {
        close(fd);
        return -1;
    }
    if (st.st_size < 0 || (size_t)st.st_size >= cap) {
        close(fd);
        return -1;
    }
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = read(fd, buf + total, (cap - 1) - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    if (out_len) {
        *out_len = total;
    }
    return 0;
}

static int read_proc_attr(const char *path, char *buf, size_t cap, size_t *out_len) {
    int fd = open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }
    size_t total = 0;
    while (total < cap - 1) {
        ssize_t n = read(fd, buf + total, (cap - 1) - total);
        if (n < 0) {
            if (errno == EINTR) continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }
    close(fd);
    buf[total] = '\0';
    if (out_len) {
        *out_len = total;
    }
    return 0;
}

static int epoll_add(int fd, uint32_t events, uint32_t tag) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = tag;
    return epoll_ctl(g_epfd, EPOLL_CTL_ADD, fd, &ev);
}

static int epoll_mod(int fd, uint32_t events, uint32_t tag) {
    struct epoll_event ev;
    memset(&ev, 0, sizeof(ev));
    ev.events = events;
    ev.data.u64 = tag;
    return epoll_ctl(g_epfd, EPOLL_CTL_MOD, fd, &ev);
}

/* Tag encoding: low 16 bits = slot index (or 0xffff for listener, 0xfffe for signalfd),
 * bit 16 = 0 for client_fd, 1 for guard_fd. */
#define TAG_LISTENER 0xFFFFU
#define TAG_SIGNALFD 0xFFFEU
#define MAKE_TAG(slot_idx, is_guard) ((uint32_t)(slot_idx) | ((uint32_t)(is_guard) << 16))
#define TAG_IS_GUARD(tag) (((tag) >> 16) & 1U)
#define TAG_SLOT(tag) ((tag) & 0xFFFFU)

static void close_slot(conn_slot_t *s) {
    if (s->guard_fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, s->guard_fd, NULL);
        close(s->guard_fd);
        s->guard_fd = -1;
    }
    if (s->client_fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, s->client_fd, NULL);
        close(s->client_fd);
        s->client_fd = -1;
    }
    s->state = ST_FREE;
    s->deadline_ms = 0;
    s->req_len = 0;
    s->req_sent = 0;
    s->resp_len = 0;
    s->resp_sent = 0;
    s->is_install_apk = 0;
    s->req_id[0] = '\0';
}

static void queue_error_reply(conn_slot_t *s, size_t slot_idx, const char *err_msg, uint64_t now_ms) {
    if (s->guard_fd >= 0) {
        epoll_ctl(g_epfd, EPOLL_CTL_DEL, s->guard_fd, NULL);
        close(s->guard_fd);
        s->guard_fd = -1;
    }
    s->resp_len = broker_format_error_json(s->req_id, err_msg, s->resp_buf, sizeof(s->resp_buf));
    s->resp_sent = 0;
    if (s->resp_len == 0) {
        close_slot(s);
        return;
    }
    s->state = ST_WRITE_CLIENT;
    s->deadline_ms = now_ms + 5000ULL;
    if (epoll_mod(s->client_fd, EPOLLOUT, MAKE_TAG(slot_idx, 0)) != 0) {
        close_slot(s);
    }
}

static int authorize_accepted_client(int cfd) {
    struct ucred cred;
    socklen_t clen = sizeof(cred);
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERCRED, &cred, &clen) != 0) {
        return -1;
    }

    char sec_buf[256];
    socklen_t slen = sizeof(sec_buf) - 1;
    if (getsockopt(cfd, SOL_SOCKET, SO_PEERSEC, sec_buf, &slen) != 0) {
        return -1;
    }
    if (slen >= sizeof(sec_buf)) {
        slen = sizeof(sec_buf) - 1;
    }
    sec_buf[slen] = '\0';

    char auth_buf[BROKER_MAX_AUTH_FILE_BYTES + 1];
    size_t auth_len = 0;
    if (read_small_nofollow(BROKER_AUTH_PATH, auth_buf, sizeof(auth_buf), &auth_len, 1) != 0) {
        return -1;
    }
    int allowed_uid = 0;
    if (broker_parse_auth_json(auth_buf, auth_len, &allowed_uid) != 0) {
        return -1;
    }
    return broker_authorize_peer((int)cred.uid, sec_buf, (size_t)slen, allowed_uid);
}

static void handle_accept(int listen_fd, uint64_t now_ms) {
    for (;;) {
        int cfd = accept4(listen_fd, NULL, NULL, SOCK_NONBLOCK | SOCK_CLOEXEC);
        if (cfd < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                return;
            }
            if (errno == EINTR) {
                continue;
            }
            return;
        }

        int free_idx = -1;
        for (int i = 0; i < MAX_CONNS; i++) {
            if (g_slots[i].state == ST_FREE) {
                free_idx = i;
                break;
            }
        }
        if (free_idx < 0 || authorize_accepted_client(cfd) != 0) {
            close(cfd);
            continue;
        }

        conn_slot_t *s = &g_slots[free_idx];
        s->client_fd = cfd;
        s->guard_fd = -1;
        s->state = ST_READ_CLIENT;
        s->deadline_ms = now_ms + 36000ULL;
        s->req_len = 0;
        s->req_sent = 0;
        s->resp_len = 0;
        s->resp_sent = 0;
        s->is_install_apk = 0;
        s->req_id[0] = '\0';

        if (epoll_add(cfd, EPOLLIN, MAKE_TAG(free_idx, 0)) != 0) {
            close_slot(s);
        }
    }
}

static void start_guard_forward(conn_slot_t *s, size_t slot_idx, uint64_t now_ms) {
    int gfd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (gfd < 0) {
        queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
        return;
    }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    size_t plen = strlen(BROKER_GUARD_SOCK_PATH);
    if (plen >= sizeof(addr.sun_path)) {
        close(gfd);
        queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
        return;
    }
    memcpy(addr.sun_path, BROKER_GUARD_SOCK_PATH, plen + 1);

    int rc = connect(gfd, (struct sockaddr *)&addr, sizeof(addr));
    if (rc == 0) {
        s->guard_fd = gfd;
        s->state = ST_WRITE_GUARD;
        s->req_sent = 0;
        s->deadline_ms = now_ms + (s->is_install_apk ? 125000ULL : 33000ULL);
        if (epoll_add(gfd, EPOLLOUT, MAKE_TAG(slot_idx, 1)) != 0) {
            close(gfd);
            s->guard_fd = -1;
            queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
            return;
        }
        /* Stop polling client_fd until reply is ready. */
        (void)epoll_mod(s->client_fd, 0, MAKE_TAG(slot_idx, 0));
        return;
    }
    if (errno == EINPROGRESS) {
        s->guard_fd = gfd;
        s->state = ST_CONNECT_GUARD;
        s->deadline_ms = now_ms + 3000ULL;
        if (epoll_add(gfd, EPOLLOUT, MAKE_TAG(slot_idx, 1)) != 0) {
            close(gfd);
            s->guard_fd = -1;
            queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
            return;
        }
        (void)epoll_mod(s->client_fd, 0, MAKE_TAG(slot_idx, 0));
        return;
    }
    close(gfd);
    queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
}

static void handle_client_read(conn_slot_t *s, size_t slot_idx, uint64_t now_ms) {
    for (;;) {
        if (s->req_len > BROKER_MAX_RPC_LINE_BYTES) {
            queue_error_reply(s, slot_idx, BROKER_LINE_TOO_LONG_MSG, now_ms);
            return;
        }
        size_t avail = (BROKER_MAX_RPC_LINE_BYTES + 1) - s->req_len;
        ssize_t n = read(s->client_fd, s->req_buf + s->req_len, avail);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close_slot(s);
            return;
        }
        if (n == 0) {
            if (s->req_len == 0) {
                queue_error_reply(s, slot_idx, "EOF", now_ms);
                return;
            }
            break; /* EOF with partial line */
        }
        size_t old_len = s->req_len;
        s->req_len += (size_t)n;
        char *nl = (char *)memchr(s->req_buf + old_len, '\n', (size_t)n);
        if (nl != NULL) {
            size_t line_len = (size_t)(nl - s->req_buf) + 1;
            s->req_len = line_len;
            break;
        }
        if (s->req_len > BROKER_MAX_RPC_LINE_BYTES) {
            queue_error_reply(s, slot_idx, BROKER_LINE_TOO_LONG_MSG, now_ms);
            return;
        }
    }

    broker_req_info_t info;
    char errbuf[192];
    if (broker_validate_rpc_request(s->req_buf, s->req_len, &info, errbuf, sizeof(errbuf)) != 0) {
        queue_error_reply(s, slot_idx, errbuf, now_ms);
        return;
    }

    if (info.trimmed_off > 0) {
        memmove(s->req_buf, s->req_buf + info.trimmed_off, info.trimmed_len);
    }
    s->req_buf[info.trimmed_len] = '\n';
    s->req_len = info.trimmed_len + 1;
    s->req_sent = 0;
    s->is_install_apk = info.is_install_apk;
    memcpy(s->req_id, info.id, sizeof(s->req_id));

    start_guard_forward(s, slot_idx, now_ms);
}

static void handle_guard_event(conn_slot_t *s, size_t slot_idx, uint32_t events, uint64_t now_ms) {
    if (s->state == ST_CONNECT_GUARD) {
        if (events & (EPOLLERR | EPOLLHUP)) {
            queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
            return;
        }
        int soerr = 0;
        socklen_t slen = sizeof(soerr);
        if (getsockopt(s->guard_fd, SOL_SOCKET, SO_ERROR, &soerr, &slen) != 0 || soerr != 0) {
            queue_error_reply(s, slot_idx, "guard unavailable", now_ms);
            return;
        }
        s->state = ST_WRITE_GUARD;
        s->req_sent = 0;
        s->deadline_ms = now_ms + (s->is_install_apk ? 125000ULL : 33000ULL);
    }

    if (s->state == ST_WRITE_GUARD) {
        while (s->req_sent < s->req_len) {
            ssize_t w = send(s->guard_fd, s->req_buf + s->req_sent, s->req_len - s->req_sent, MSG_NOSIGNAL);
            if (w < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) return;
                queue_error_reply(s, slot_idx, "guard write failed", now_ms);
                return;
            }
            s->req_sent += (size_t)w;
        }
        s->state = ST_READ_GUARD;
        s->resp_len = 0;
        if (epoll_mod(s->guard_fd, EPOLLIN, MAKE_TAG(slot_idx, 1)) != 0) {
            queue_error_reply(s, slot_idx, "guard read failed", now_ms);
        }
        return;
    }

    if (s->state == ST_READ_GUARD) {
        int line_done = 0;
        for (;;) {
            if (s->resp_len > BROKER_MAX_RPC_RESP_BYTES) {
                queue_error_reply(s, slot_idx, "guard read failed", now_ms);
                return;
            }
            size_t avail = (BROKER_MAX_RPC_RESP_BYTES + 1) - s->resp_len;
            ssize_t n = read(s->guard_fd, s->resp_buf + s->resp_len, avail);
            if (n < 0) {
                if (errno == EINTR) continue;
                if (errno == EAGAIN || errno == EWOULDBLOCK) break;
                queue_error_reply(s, slot_idx, "guard read failed", now_ms);
                return;
            }
            if (n == 0) {
                if (s->resp_len == 0) {
                    queue_error_reply(s, slot_idx, "guard read failed", now_ms);
                    return;
                }
                line_done = 1;
                break;
            }
            size_t old_len = s->resp_len;
            s->resp_len += (size_t)n;
            char *nl = (char *)memchr(s->resp_buf + old_len, '\n', (size_t)n);
            if (nl != NULL) {
                s->resp_len = (size_t)(nl - s->resp_buf) + 1;
                line_done = 1;
                break;
            }
            if (s->resp_len > BROKER_MAX_RPC_RESP_BYTES) {
                queue_error_reply(s, slot_idx, "guard read failed", now_ms);
                return;
            }
        }
        if (!line_done) {
            return;
        }

        size_t off = 0;
        size_t end = s->resp_len;
        while (off < end && (s->resp_buf[off] == ' ' || s->resp_buf[off] == '\t' ||
                             s->resp_buf[off] == '\r' || s->resp_buf[off] == '\n')) {
            off++;
        }
        while (end > off && (s->resp_buf[end - 1] == ' ' || s->resp_buf[end - 1] == '\t' ||
                             s->resp_buf[end - 1] == '\r' || s->resp_buf[end - 1] == '\n')) {
            end--;
        }
        size_t clean_len = end - off;
        if (clean_len > BROKER_MAX_RPC_RESP_BYTES - 1) {
            clean_len = BROKER_MAX_RPC_RESP_BYTES - 1;
        }
        if (off > 0 && clean_len > 0) {
            memmove(s->resp_buf, s->resp_buf + off, clean_len);
        }
        s->resp_buf[clean_len] = '\n';
        s->resp_len = clean_len + 1;
        s->resp_sent = 0;

        epoll_ctl(g_epfd, EPOLL_CTL_DEL, s->guard_fd, NULL);
        close(s->guard_fd);
        s->guard_fd = -1;

        s->state = ST_WRITE_CLIENT;
        s->deadline_ms = now_ms + 5000ULL;
        if (epoll_mod(s->client_fd, EPOLLOUT, MAKE_TAG(slot_idx, 0)) != 0) {
            close_slot(s);
        }
    }
}

static void handle_client_write(conn_slot_t *s) {
    while (s->resp_sent < s->resp_len) {
        ssize_t w = send(s->client_fd, s->resp_buf + s->resp_sent, s->resp_len - s->resp_sent, MSG_NOSIGNAL);
        if (w < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) return;
            close_slot(s);
            return;
        }
        s->resp_sent += (size_t)w;
    }
    close_slot(s);
}

int main(void) {
    signal(SIGPIPE, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    char attr_buf[256];
    size_t attr_len = 0;
    if (read_proc_attr(BROKER_PROC_ATTR_CURRENT, attr_buf, sizeof(attr_buf), &attr_len) != 0 ||
        broker_check_self_context(attr_buf, attr_len) != 0) {
        log_stderr("unexpected SELinux context (want " BROKER_SELINUX_CTX ")");
        return 1;
    }

    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGTERM);
    sigaddset(&mask, SIGINT);
    if (sigprocmask(SIG_BLOCK, &mask, NULL) != 0) {
        log_stderr("sigprocmask failed");
        return 1;
    }
    int sig_fd = signalfd(-1, &mask, SFD_NONBLOCK | SFD_CLOEXEC);
    if (sig_fd < 0) {
        log_stderr("signalfd failed");
        return 1;
    }

    unlink(BROKER_SOCK_PATH);
    mode_t old_mask = umask(0000);
    int listen_fd = socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
    if (listen_fd < 0) {
        umask(old_mask);
        log_stderr("socket failed");
        close(sig_fd);
        return 1;
    }

    struct sockaddr_un laddr;
    memset(&laddr, 0, sizeof(laddr));
    laddr.sun_family = AF_UNIX;
    memcpy(laddr.sun_path, BROKER_SOCK_PATH, strlen(BROKER_SOCK_PATH) + 1);
    if (bind(listen_fd, (struct sockaddr *)&laddr, sizeof(laddr)) != 0 ||
        listen(listen_fd, 16) != 0) {
        umask(old_mask);
        log_stderr("bind/listen failed");
        close(listen_fd);
        unlink(BROKER_SOCK_PATH);
        close(sig_fd);
        return 1;
    }
    umask(old_mask);
    if (chmod(BROKER_SOCK_PATH, 0666) != 0) {
        log_stderr("chmod ctrl.sock failed");
        close(listen_fd);
        unlink(BROKER_SOCK_PATH);
        close(sig_fd);
        return 1;
    }

    g_epfd = epoll_create1(EPOLL_CLOEXEC);
    if (g_epfd < 0) {
        log_stderr("epoll_create1 failed");
        close(listen_fd);
        unlink(BROKER_SOCK_PATH);
        close(sig_fd);
        return 1;
    }
    for (int i = 0; i < MAX_CONNS; i++) {
        g_slots[i].client_fd = -1;
        g_slots[i].guard_fd = -1;
        g_slots[i].state = ST_FREE;
    }
    if (epoll_add(listen_fd, EPOLLIN, TAG_LISTENER) != 0 ||
        epoll_add(sig_fd, EPOLLIN, TAG_SIGNALFD) != 0) {
        log_stderr("epoll_add failed");
        close(g_epfd);
        close(listen_fd);
        unlink(BROKER_SOCK_PATH);
        close(sig_fd);
        return 1;
    }

    int running = 1;
    struct epoll_event events[MAX_EPOLL_EVENTS];
    while (running) {
        uint64_t now_ms = monotonic_ms();
        int timeout_ms = -1;
        for (int i = 0; i < MAX_CONNS; i++) {
            if (g_slots[i].state == ST_FREE) continue;
            int rem = (g_slots[i].deadline_ms > now_ms)
                ? (int)(g_slots[i].deadline_ms - now_ms)
                : 0;
            if (timeout_ms < 0 || rem < timeout_ms) {
                timeout_ms = rem;
            }
        }

        int nev = epoll_wait(g_epfd, events, MAX_EPOLL_EVENTS, timeout_ms);
        if (nev < 0) {
            if (errno == EINTR) continue;
            break;
        }
        now_ms = monotonic_ms();

        for (int i = 0; i < nev; i++) {
            uint32_t tag = (uint32_t)events[i].data.u64;
            uint32_t ev = events[i].events;

            if (tag == TAG_SIGNALFD) {
                struct signalfd_siginfo si;
                while (read(sig_fd, &si, sizeof(si)) > 0) {
                }
                running = 0;
                break;
            }
            if (tag == TAG_LISTENER) {
                handle_accept(listen_fd, now_ms);
                continue;
            }
            size_t slot_idx = TAG_SLOT(tag);
            if (slot_idx >= MAX_CONNS) continue;
            conn_slot_t *s = &g_slots[slot_idx];
            if (s->state == ST_FREE) continue;

            if (TAG_IS_GUARD(tag)) {
                handle_guard_event(s, slot_idx, ev, now_ms);
            } else {
                if (s->state == ST_READ_CLIENT) {
                    if (ev & (EPOLLIN | EPOLLHUP | EPOLLERR)) {
                        handle_client_read(s, slot_idx, now_ms);
                    }
                } else if (s->state == ST_WRITE_CLIENT) {
                    if (ev & (EPOLLOUT | EPOLLERR | EPOLLHUP)) {
                        handle_client_write(s);
                    }
                }
            }
        }

        now_ms = monotonic_ms();
        for (int i = 0; i < MAX_CONNS; i++) {
            conn_slot_t *s = &g_slots[i];
            if (s->state != ST_FREE && now_ms >= s->deadline_ms) {
                close_slot(s);
            }
        }
    }

    for (int i = 0; i < MAX_CONNS; i++) {
        close_slot(&g_slots[i]);
    }
    close(g_epfd);
    close(listen_fd);
    unlink(BROKER_SOCK_PATH);
    close(sig_fd);
    return 0;
}

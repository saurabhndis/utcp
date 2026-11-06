/* Kernel backend: non-blocking sockets, edge-triggered epoll, one
 * SO_REUSEPORT listener per worker. Tuned to be a fair baseline. */
#include "app.h"

#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#define MAXEV 256

struct ksock {
    int fd;
    int listener;
    int connecting;
    int dead;
    void *user;
    struct ksock *next_dead;
};

struct kbe {
    int ep;
    struct ksock lsn;
    struct ksock *dead; /* freed after the current epoll batch */
};

static int k_init(struct worker *w)
{
    static struct kbe k;
    memset(&k, 0, sizeof(k));
    k.ep = epoll_create1(0);
    if (k.ep < 0)
        return -1;
    w->be = &k;
    return 0;
}

static void tune(struct worker *w, int fd)
{
    int one = 1;
    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    if (w->o->sndbuf) {
        int v = (int)w->o->sndbuf;
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &v, sizeof(v));
    }
    if (w->o->rcvbuf) {
        int v = (int)w->o->rcvbuf;
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &v, sizeof(v));
    }
    if (w->o->busy_poll) {
        int us = 50;
        setsockopt(fd, SOL_SOCKET, SO_BUSY_POLL, &us, sizeof(us));
    }
}

static int k_listen(struct worker *w, uint16_t port)
{
    struct kbe *k = w->be;
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int one = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one));
    tune(w, fd);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port),
                            .sin_addr.s_addr = w->o->local_ip};
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0 || listen(fd, 65535) < 0) {
        perror("bind/listen");
        close(fd);
        return -1;
    }
    k->lsn.fd = fd;
    k->lsn.listener = 1;
    struct epoll_event ev = {.events = EPOLLIN | EPOLLET, .data.ptr = &k->lsn};
    epoll_ctl(k->ep, EPOLL_CTL_ADD, fd, &ev);
    return 0;
}

static struct ksock *ks_new(struct worker *w, int fd)
{
    struct kbe *k = w->be;
    struct ksock *s = calloc(1, sizeof(*s));
    s->fd = fd;
    struct epoll_event ev = {.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLET, .data.ptr = s};
    epoll_ctl(k->ep, EPOLL_CTL_ADD, fd, &ev);
    return s;
}

static void *k_connect(struct worker *w, uint32_t ip, uint16_t port)
{
    int fd = socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0)
        return NULL;
    tune(w, fd);
    struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port), .sin_addr.s_addr = ip};
    if (connect(fd, (struct sockaddr *)&a, sizeof(a)) < 0 && errno != EINPROGRESS) {
        close(fd);
        return NULL;
    }
    struct ksock *s = ks_new(w, fd);
    s->connecting = 1;
    return s;
}

static ssize_t k_send(struct worker *w, void *h, const void *b, size_t n)
{
    (void)w;
    struct ksock *s = h;
    return send(s->fd, b, n, MSG_NOSIGNAL | MSG_DONTWAIT);
}

static ssize_t k_recv(struct worker *w, void *h, void *b, size_t n)
{
    (void)w;
    struct ksock *s = h;
    return recv(s->fd, b, n, MSG_DONTWAIT);
}

static void k_shutdown(struct worker *w, void *h)
{
    (void)w;
    shutdown(((struct ksock *)h)->fd, SHUT_WR);
}

static void k_close(struct worker *w, void *h)
{
    struct kbe *k = w->be;
    struct ksock *s = h;
    epoll_ctl(k->ep, EPOLL_CTL_DEL, s->fd, NULL);
    close(s->fd);
    s->user = NULL;
    s->dead = 1;
    s->next_dead = k->dead;
    k->dead = s;
}

static void k_set_user(struct worker *w, void *h, void *user)
{
    (void)w;
    ((struct ksock *)h)->user = user;
}

static int k_run(struct worker *w, int timeout_us)
{
    struct kbe *k = w->be;
    struct epoll_event ev[MAXEV];
    int to = w->o->busy_poll ? 0 : (timeout_us + 999) / 1000;
    uint64_t t0 = now_ns();
    int n = epoll_wait(k->ep, ev, MAXEV, to);
    uint64_t t1 = now_ns();
    atomic_fetch_add_explicit(&w->st->io_ns, t1 - t0, memory_order_relaxed);
    for (int i = 0; i < n; i++) {
        struct ksock *s = ev[i].data.ptr;
        if (s->listener) {
            for (;;) {
                int fd = accept4(s->fd, NULL, NULL, SOCK_NONBLOCK);
                if (fd < 0)
                    break;
                tune(w, fd);
                wl_on_accept(w, ks_new(w, fd));
            }
            continue;
        }
        uint32_t e = ev[i].events;
        if (s->dead || !s->user)
            continue;
        if (s->connecting && (e & (EPOLLOUT | EPOLLERR | EPOLLHUP))) {
            int err = 0;
            socklen_t l = sizeof(err);
            getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &l);
            s->connecting = 0;
            if (err) {
                wl_on_closed(w, s->user, err);
                continue;
            }
            wl_on_connected(w, s->user);
            if (!s->user)
                continue;
        }
        if (e & (EPOLLIN | EPOLLRDHUP | EPOLLHUP | EPOLLERR))
            wl_on_readable(w, s->user);
        if (s->user && (e & EPOLLOUT))
            wl_on_writable(w, s->user);
    }
    while (k->dead) {
        struct ksock *d = k->dead;
        k->dead = d->next_dead;
        free(d);
    }
    return n;
}

const struct transport tp_kernel = {
    .name = "kernel",
    .init = k_init,
    .listen = k_listen,
    .connect = k_connect,
    .send = k_send,
    .recv = k_recv,
    .shutdown_wr = k_shutdown,
    .close = k_close,
    .set_user = k_set_user,
    .run = k_run,
};

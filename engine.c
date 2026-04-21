/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>
#include "monitor_ioctl.h"

#define STACK_SIZE          (1024 * 1024)
#define CONTAINER_ID_LEN    32
#define CONTROL_PATH        "/tmp/mini_runtime.sock"
#define LOG_DIR             "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN   256
#define LOG_CHUNK_SIZE      4096
#define LOG_BUFFER_CAPACITY 64
#define DEFAULT_SOFT_LIMIT  (40UL << 20)
#define DEFAULT_HARD_LIMIT  (64UL << 20)
#define MAX_CONTAINERS      64

/* ── command / state enums ── */
typedef enum {
    CMD_SUPERVISOR = 0, CMD_START, CMD_RUN, CMD_PS, CMD_LOGS, CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

/* ── per-container metadata ── */
typedef struct container_record {
    char              id[CONTAINER_ID_LEN];
    pid_t             host_pid;
    time_t            started_at;
    container_state_t state;
    unsigned long     soft_limit_bytes;
    unsigned long     hard_limit_bytes;
    int               exit_code;
    int               exit_signal;
    int               stop_requested;   /* set before sending SIGTERM/SIGKILL */
    char              log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

/* ── bounded log buffer ── */
typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head, tail, count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} bounded_buffer_t;

/* ── IPC messages ── */
typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

/* ── config passed into clone child ── */
typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  log_write_fd;   /* write-end of pipe → supervisor reads logs */
} child_config_t;

/* ── per-container producer thread arg ── */
typedef struct {
    int              read_fd;   /* read-end of the container's pipe  */
    char             container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *buf;
} producer_arg_t;

/* ── supervisor context ── */
typedef struct {
    int               server_fd;
    int               monitor_fd;
    int               should_stop;
    pthread_t         logger_thread;
    bounded_buffer_t  log_buffer;
    pthread_mutex_t   metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* global so signal handlers can reach it */
static supervisor_ctx_t *g_ctx = NULL;

/* ═══════════════════════════════════════════════════════════════
 * Utilities
 * ═══════════════════════════════════════════════════════════════ */
static void usage(const char *prog)
{
    fprintf(stderr,
        "Usage:\n"
        "  %s supervisor <base-rootfs>\n"
        "  %s start <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s run   <id> <rootfs> <cmd> [--soft-mib N] [--hard-mib N] [--nice N]\n"
        "  %s ps\n"
        "  %s logs <id>\n"
        "  %s stop <id>\n",
        prog, prog, prog, prog, prog, prog);
}

static const char *state_str(container_state_t s)
{
    switch (s) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

static int parse_mib_flag(const char *flag, const char *val,
                           unsigned long *out)
{
    char *end; errno = 0;
    unsigned long v = strtoul(val, &end, 10);
    if (errno || end == val || *end) {
        fprintf(stderr, "Bad value for %s: %s\n", flag, val); return -1;
    }
    *out = v << 20; return 0;
}

static int parse_optional_flags(control_request_t *req,
                                  int argc, char *argv[], int start)
{
    for (int i = start; i < argc; i += 2) {
        if (i + 1 >= argc) { fprintf(stderr,"Missing value for %s\n",argv[i]); return -1; }
        if (!strcmp(argv[i],"--soft-mib")) { if (parse_mib_flag("--soft-mib",argv[i+1],&req->soft_limit_bytes)) return -1; }
        else if (!strcmp(argv[i],"--hard-mib")) { if (parse_mib_flag("--hard-mib",argv[i+1],&req->hard_limit_bytes)) return -1; }
        else if (!strcmp(argv[i],"--nice")) {
            char *e; long n = strtol(argv[i+1],&e,10);
            if (*e || n < -20 || n > 19) { fprintf(stderr,"Bad --nice value\n"); return -1; }
            req->nice_value = (int)n;
        } else { fprintf(stderr,"Unknown option: %s\n",argv[i]); return -1; }
    }
    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr,"soft limit cannot exceed hard limit\n"); return -1;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Bounded Buffer  (Task 3)
 * ═══════════════════════════════════════════════════════════════ */
static int bounded_buffer_init(bounded_buffer_t *b)
{
    memset(b, 0, sizeof(*b));
    int r;
    if ((r = pthread_mutex_init(&b->mutex, NULL))) return r;
    if ((r = pthread_cond_init(&b->not_empty, NULL))) { pthread_mutex_destroy(&b->mutex); return r; }
    if ((r = pthread_cond_init(&b->not_full,  NULL))) {
        pthread_cond_destroy(&b->not_empty); pthread_mutex_destroy(&b->mutex); return r;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *b)
{
    pthread_cond_destroy(&b->not_full);
    pthread_cond_destroy(&b->not_empty);
    pthread_mutex_destroy(&b->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *b)
{
    pthread_mutex_lock(&b->mutex);
    b->shutting_down = 1;
    pthread_cond_broadcast(&b->not_empty);
    pthread_cond_broadcast(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
}

/* Returns 0 on success, -1 if shutting down */
int bounded_buffer_push(bounded_buffer_t *b, const log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    /* wait while full (but not if shutting down) */
    while (b->count == LOG_BUFFER_CAPACITY && !b->shutting_down)
        pthread_cond_wait(&b->not_full, &b->mutex);

    if (b->shutting_down) {
        pthread_mutex_unlock(&b->mutex);
        return -1;
    }
    b->items[b->tail] = *item;
    b->tail = (b->tail + 1) % LOG_BUFFER_CAPACITY;
    b->count++;
    pthread_cond_signal(&b->not_empty);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* Returns 0 on success, -1 if shutting down AND buffer empty */
int bounded_buffer_pop(bounded_buffer_t *b, log_item_t *item)
{
    pthread_mutex_lock(&b->mutex);
    while (b->count == 0) {
        if (b->shutting_down) { pthread_mutex_unlock(&b->mutex); return -1; }
        pthread_cond_wait(&b->not_empty, &b->mutex);
    }
    *item = b->items[b->head];
    b->head = (b->head + 1) % LOG_BUFFER_CAPACITY;
    b->count--;
    pthread_cond_signal(&b->not_full);
    pthread_mutex_unlock(&b->mutex);
    return 0;
}

/* ── Consumer thread: pop items → write to log file ── */
void *logging_thread(void *arg)
{
    bounded_buffer_t *buf = (bounded_buffer_t *)arg;
    log_item_t item;

    /* make sure log directory exists */
    mkdir(LOG_DIR, 0755);

    while (1) {
        if (bounded_buffer_pop(buf, &item) != 0)
            break;   /* shutdown + empty */

        /* build log path  logs/<id>.log */
        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);

        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) continue;
        write(fd, item.data, item.length);
        close(fd);
    }
    /* drain any remaining items after shutdown signal */
    while (1) {
        pthread_mutex_lock(&buf->mutex);
        if (buf->count == 0) { pthread_mutex_unlock(&buf->mutex); break; }
        item = buf->items[buf->head];
        buf->head = (buf->head + 1) % LOG_BUFFER_CAPACITY;
        buf->count--;
        pthread_mutex_unlock(&buf->mutex);

        char path[PATH_MAX];
        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR, item.container_id);
        int fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd >= 0) { write(fd, item.data, item.length); close(fd); }
    }
    return NULL;
}

/* ── Producer thread: read pipe → push into buffer ── */
static void *producer_thread(void *arg)
{
    producer_arg_t *pa = (producer_arg_t *)arg;
    char tmp[LOG_CHUNK_SIZE];
    ssize_t n;

    while ((n = read(pa->read_fd, tmp, sizeof(tmp))) > 0) {
        log_item_t item;
        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, pa->container_id, CONTAINER_ID_LEN - 1);
        item.length = (size_t)n;
        memcpy(item.data, tmp, (size_t)n);
        bounded_buffer_push(pa->buf, &item);
    }
    close(pa->read_fd);
    free(pa);
    return NULL;
}

/* ═══════════════════════════════════════════════════════════════
 * Container child  (Task 1)
 * ═══════════════════════════════════════════════════════════════ */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* redirect stdout + stderr into the logging pipe */
    dup2(cfg->log_write_fd, STDOUT_FILENO);
    dup2(cfg->log_write_fd, STDERR_FILENO);
    close(cfg->log_write_fd);

    /* set hostname */
    if (sethostname(cfg->id, strlen(cfg->id)) != 0)
        perror("sethostname");

    /* chroot */
    if (chroot(cfg->rootfs) != 0) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") != 0) {
        perror("chdir");
        return 1;
    }

    /* mount /proc */
    mkdir("/proc", 0555);
    if (mount("proc", "/proc", "proc", 0, NULL) != 0)
        perror("mount /proc");

    /* apply nice */
    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    /* 🚀 EXEC USING SHELL (FIXES YOUR ISSUE) */
    char *argv[] = { cfg->command, NULL };
execvp(cfg->command, argv);

perror("execvp failed");
return 1;

    /* only reached if exec fails */
    perror("execvp failed");
    return 1;
}

/* ═══════════════════════════════════════════════════════════════
 * Monitor ioctl helpers  (Task 4)
 * ═══════════════════════════════════════════════════════════════ */
int register_with_monitor(int monitor_fd, const char *id, pid_t pid,
                           unsigned long soft, unsigned long hard)
{
    if (monitor_fd < 0) return 0;
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    req.soft_limit_bytes = soft;
    req.hard_limit_bytes = hard;
    strncpy(req.container_id, id, MONITOR_NAME_LEN - 1);
    return ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0 ? -1 : 0;
}

int unregister_from_monitor(int monitor_fd, const char *id, pid_t pid)
{
    if (monitor_fd < 0) return 0;
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = pid;
    strncpy(req.container_id, id, MONITOR_NAME_LEN - 1);
    return ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0 ? -1 : 0;
}

/* ═══════════════════════════════════════════════════════════════
 * Metadata helpers
 * ═══════════════════════════════════════════════════════════════ */
static container_record_t *find_container(supervisor_ctx_t *ctx, const char *id)
{
    /* called with metadata_lock held */
    for (container_record_t *c = ctx->containers; c; c = c->next)
        if (!strcmp(c->id, id)) return c;
    return NULL;
}

static void reap_children(supervisor_ctx_t *ctx)
{
    int status;
    pid_t pid;
    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pthread_mutex_lock(&ctx->metadata_lock);
        for (container_record_t *c = ctx->containers; c; c = c->next) {
            if (c->host_pid != pid) continue;
            if (WIFEXITED(status)) {
                c->exit_code   = WEXITSTATUS(status);
                c->exit_signal = 0;
                c->state       = c->stop_requested ? CONTAINER_STOPPED : CONTAINER_EXITED;
            } else if (WIFSIGNALED(status)) {
                c->exit_signal = WTERMSIG(status);
                c->exit_code   = 128 + c->exit_signal;
                /* hard-limit kill: SIGKILL without stop_requested */
                if (c->exit_signal == SIGKILL && !c->stop_requested)
                    c->state = CONTAINER_KILLED;
                else
                    c->state = CONTAINER_STOPPED;
            }
            unregister_from_monitor(ctx->monitor_fd, c->id, pid);
            break;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

/* ═══════════════════════════════════════════════════════════════
 * Signal handling
 * ═══════════════════════════════════════════════════════════════ */
static void sigchld_handler(int sig)
{
    (void)sig;
    if (g_ctx) reap_children(g_ctx);
}

static void sigterm_handler(int sig)
{
    (void)sig;
    if (g_ctx) g_ctx->should_stop = 1;
}

/* ═══════════════════════════════════════════════════════════════
 * Supervisor: handle one connected CLI client  (Task 2)
 * ═══════════════════════════════════════════════════════════════ */
static void handle_start(supervisor_ctx_t *ctx,
                          const control_request_t *req,
                          control_response_t *resp,
                          int is_run)
{
    /* check for duplicate id */
    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container(ctx, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message),
                 "Container '%s' already exists", req->container_id);
        return;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* create pipe: container stdout/stderr → supervisor */
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        resp->status = -1; strcpy(resp->message, "pipe() failed"); return;
    }

    /* allocate child config on heap (child will use it, then supervisor frees after clone returns) */
    child_config_t *cfg = calloc(1, sizeof(*cfg));
    strncpy(cfg->id,      req->container_id, CONTAINER_ID_LEN - 1);
    strncpy(cfg->rootfs,  req->rootfs,       PATH_MAX - 1);
    strncpy(cfg->command, req->command,      CHILD_COMMAND_LEN - 1);
    cfg->nice_value    = req->nice_value;
    cfg->log_write_fd  = pipefd[1];

    /* allocate clone stack */
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        free(cfg); close(pipefd[0]); close(pipefd[1]);
        resp->status = -1; strcpy(resp->message, "malloc stack failed"); return;
    }

    int flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid_t pid = clone(child_fn, stack + STACK_SIZE, flags, cfg);
    free(stack);
    close(pipefd[1]);   /* supervisor doesn't write to child */

    if (pid < 0) {
        free(cfg); close(pipefd[0]);
        resp->status = -1; snprintf(resp->message, sizeof(resp->message),
                                    "clone failed: %s", strerror(errno));
        return;
    }
    free(cfg);   /* child has its own copy of the stack data */

    /* build metadata record */
    container_record_t *rec = calloc(1, sizeof(*rec));
    strncpy(rec->id, req->container_id, CONTAINER_ID_LEN - 1);
    rec->host_pid          = pid;
    rec->started_at        = time(NULL);
    rec->state             = CONTAINER_RUNNING;
    rec->soft_limit_bytes  = req->soft_limit_bytes;
    rec->hard_limit_bytes  = req->hard_limit_bytes;
    snprintf(rec->log_path, sizeof(rec->log_path), "%s/%s.log",
             LOG_DIR, req->container_id);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* register with kernel monitor */
    register_with_monitor(ctx->monitor_fd, req->container_id, pid,
                           req->soft_limit_bytes, req->hard_limit_bytes);

    /* spawn producer thread for this container's pipe */
    producer_arg_t *pa = malloc(sizeof(*pa));
    pa->read_fd = pipefd[0];
    strncpy(pa->container_id, req->container_id, CONTAINER_ID_LEN - 1);
    pa->buf = &ctx->log_buffer;
    pthread_t pt;
    pthread_create(&pt, NULL, producer_thread, pa);
    pthread_detach(pt);
    fprintf(stderr, "[supervisor] launched container '%s' pid=%d\n", req->container_id, (int)pid);

    resp->status = 0;
    if (is_run) {
        /* For 'run': tell client the PID; client will wait for exit */
        snprintf(resp->message, sizeof(resp->message),
                 "started pid=%d", (int)pid);
    } else {
        snprintf(resp->message, sizeof(resp->message),
                 "Container '%s' started (pid=%d)", req->container_id, (int)pid);
    }
}

static void handle_ps(supervisor_ctx_t *ctx, control_response_t *resp)
{
    /* We'll send a multi-line table back in resp->message.
       For large outputs this is fine for demo purposes. */
    char buf[4096];
    int  off = 0;
    off += snprintf(buf + off, sizeof(buf) - off,
                    "%-16s %-8s %-10s %-8s %-10s %-10s\n",
                    "ID", "PID", "STATE", "EXIT", "SOFT_MIB", "HARD_MIB");

    pthread_mutex_lock(&ctx->metadata_lock);
    for (container_record_t *c = ctx->containers; c && off < (int)sizeof(buf)-1; c = c->next) {
        off += snprintf(buf + off, sizeof(buf) - off,
                        "%-16s %-8d %-10s %-8d %-10lu %-10lu\n",
                        c->id, (int)c->host_pid, state_str(c->state),
                        c->exit_code,
                        c->soft_limit_bytes >> 20,
                        c->hard_limit_bytes >> 20);
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    resp->status = 0;
    strncpy(resp->message, buf, sizeof(resp->message) - 1);
}

static void handle_logs(supervisor_ctx_t *ctx, const control_request_t *req,
                         control_response_t *resp)
{
    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *c = find_container(ctx, req->container_id);
    char path[PATH_MAX];
    if (c) strncpy(path, c->log_path, PATH_MAX - 1);
    pthread_mutex_unlock(&ctx->metadata_lock);

    if (!c) {
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message),
                 "No container '%s'", req->container_id);
        return;
    }

    /* send log path back; client can cat it or we stream it */
    resp->status = 0;
    snprintf(resp->message, sizeof(resp->message), "log:%s", path);
}

static void handle_stop(supervisor_ctx_t *ctx, const control_request_t *req,
                          control_response_t *resp)
{
    pthread_mutex_lock(&ctx->metadata_lock);
    container_record_t *c = find_container(ctx, req->container_id);
    if (!c || c->state != CONTAINER_RUNNING) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp->status = -1;
        snprintf(resp->message, sizeof(resp->message),
                 "Container '%s' not running", req->container_id);
        return;
    }
    c->stop_requested = 1;
    pid_t pid = c->host_pid;
    pthread_mutex_unlock(&ctx->metadata_lock);

    kill(pid, SIGTERM);
    resp->status = 0;
    snprintf(resp->message, sizeof(resp->message),
             "SIGTERM sent to '%s' (pid=%d)", req->container_id, (int)pid);
}

static void handle_client(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t  req;
    control_response_t resp;
    memset(&resp, 0, sizeof(resp));

    ssize_t n = recv(client_fd, &req, sizeof(req), 0);
    if (n != (ssize_t)sizeof(req)) {
        resp.status = -1; strcpy(resp.message, "malformed request");
        send(client_fd, &resp, sizeof(resp), 0);
        return;
    }

    switch (req.kind) {
    case CMD_START: handle_start(ctx, &req, &resp, 0); break;
    case CMD_RUN:   handle_start(ctx, &req, &resp, 1); break;
    case CMD_PS:    handle_ps(ctx, &resp);              break;
    case CMD_LOGS:  handle_logs(ctx, &req, &resp);      break;
    case CMD_STOP:  handle_stop(ctx, &req, &resp);      break;
    default:
        resp.status = -1; strcpy(resp.message, "unknown command");
    }

    send(client_fd, &resp, sizeof(resp), 0);
}

/* ═══════════════════════════════════════════════════════════════
 * Supervisor main loop  (Task 1 + 2)
 * ═══════════════════════════════════════════════════════════════ */
static int run_supervisor(const char *rootfs)
{
    (void)rootfs;   /* base rootfs noted; per-container rootfs comes via CLI */

    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    /* init synchronisation */
    pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (bounded_buffer_init(&ctx.log_buffer) != 0) {
        perror("bounded_buffer_init"); return 1;
    }

    /* open kernel monitor (optional — if module not loaded, continue) */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "[supervisor] /dev/container_monitor not available"
                        " — continuing without memory limits\n");

    /* create log directory */
    mkdir(LOG_DIR, 0755);

    /* UNIX domain socket for CLI control channel */
    unlink(CONTROL_PATH);
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); return 1;
    }
    if (listen(ctx.server_fd, 16) < 0) { perror("listen"); return 1; }

    /* signals */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigchld_handler;
    sa.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = sigterm_handler;
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGINT,  &sa, NULL);

    /* start logger consumer thread */
    pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx.log_buffer);

    fprintf(stderr, "[supervisor] ready. base-rootfs=%s socket=%s\n", rootfs, CONTROL_PATH);

    /* make server_fd non-blocking so accept() doesn't block forever */
    fcntl(ctx.server_fd, F_SETFL, O_NONBLOCK);

    while (!ctx.should_stop) {
        int client = accept(ctx.server_fd, NULL, NULL);
        if (client < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                /* no pending connection — reap children and sleep briefly */
                reap_children(&ctx);
                usleep(50000);   /* 50 ms */
                continue;
            }
            if (errno == EINTR) continue;
            perror("accept"); break;
        }
        handle_client(&ctx, client);
        close(client);
    }

    fprintf(stderr, "[supervisor] Shutting down...\n");

    /* stop all running containers */
    pthread_mutex_lock(&ctx.metadata_lock);
    for (container_record_t *c = ctx.containers; c; c = c->next) {
        if (c->state == CONTAINER_RUNNING) {
            c->stop_requested = 1;
            kill(c->host_pid, SIGTERM);
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* wait for children */
    while (waitpid(-1, NULL, 0) > 0);

    /* stop logger */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    pthread_join(ctx.logger_thread, NULL);
    bounded_buffer_destroy(&ctx.log_buffer);

    /* free metadata */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *c = ctx.containers;
    while (c) { container_record_t *n = c->next; free(c); c = n; }
    pthread_mutex_unlock(&ctx.metadata_lock);
    pthread_mutex_destroy(&ctx.metadata_lock);

    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);
    close(ctx.server_fd);
    unlink(CONTROL_PATH);

    fprintf(stderr, "[supervisor] Clean exit.\n");
    return 0;
}

/* ═══════════════════════════════════════════════════════════════
 * CLI client side  (Task 2)
 * ═══════════════════════════════════════════════════════════════ */
static int send_control_request(const control_request_t *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "Cannot connect to supervisor at %s\n"
                        "Is the supervisor running?\n", CONTROL_PATH);
        close(fd); return 1;
    }

    send(fd, req, sizeof(*req), 0);

    control_response_t resp;
    ssize_t n = recv(fd, &resp, sizeof(resp), 0);
    close(fd);

    if (n != (ssize_t)sizeof(resp)) {
        fprintf(stderr, "Unexpected response size\n"); return 1;
    }

    /* handle 'logs' response: stream the file */
    if (req->kind == CMD_LOGS && resp.status == 0 &&
        strncmp(resp.message, "log:", 4) == 0) {
        const char *path = resp.message + 4;
        FILE *f = fopen(path, "r");
        if (!f) { fprintf(stderr, "Cannot open log: %s\n", path); return 1; }
        char line[512];
        while (fgets(line, sizeof(line), f)) fputs(line, stdout);
        fclose(f);
        return 0;
    }

    /* handle 'run': wait for container to exit */
    if (req->kind == CMD_RUN && resp.status == 0) {
        /* parse pid from "started pid=NNN" */
        int pid = 0;
        sscanf(resp.message, "started pid=%d", &pid);
        printf("%s\n", resp.message);
        if (pid > 0) {
            /* poll supervisor ps until container is no longer running */
            control_request_t ps_req;
            memset(&ps_req, 0, sizeof(ps_req));
            ps_req.kind = CMD_PS;
            while (1) {
                usleep(200000);
                int pfd = socket(AF_UNIX, SOCK_STREAM, 0);
                connect(pfd, (struct sockaddr *)&addr, sizeof(addr));
                send(pfd, &ps_req, sizeof(ps_req), 0);
                control_response_t pr;
                recv(pfd, &pr, sizeof(pr), 0);
                close(pfd);
                /* check if our container id is still 'running' */
                if (!strstr(pr.message, req->container_id) ||
                    !strstr(pr.message, "running"))
                    break;
            }
        }
        return 0;
    }

    printf("%s\n", resp.message);
    return resp.status == 0 ? 0 : 1;
}

/* ═══════════════════════════════════════════════════════════════
 * CLI command entry points
 * ═══════════════════════════════════════════════════════════════ */
static int cmd_start(int argc, char *argv[])
{
    if (argc < 5) { usage(argv[0]); return 1; }
    control_request_t req; memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    strncpy(req.rootfs,       argv[3], PATH_MAX - 1);
    strncpy(req.command,      argv[4], CHILD_COMMAND_LEN - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5)) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    if (argc < 5) { usage(argv[0]); return 1; }
    control_request_t req; memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    strncpy(req.rootfs,       argv[3], PATH_MAX - 1);
    strncpy(req.command,      argv[4], CHILD_COMMAND_LEN - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5)) return 1;
    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req; memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;
    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    if (argc < 3) { fprintf(stderr,"Usage: %s logs <id>\n", argv[0]); return 1; }
    control_request_t req; memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    if (argc < 3) { fprintf(stderr,"Usage: %s stop <id>\n", argv[0]); return 1; }
    control_request_t req; memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], CONTAINER_ID_LEN - 1);
    return send_control_request(&req);
}

/* ═══════════════════════════════════════════════════════════════
 * main
 * ═══════════════════════════════════════════════════════════════ */
int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }
    if (!strcmp(argv[1], "supervisor")) {
        if (argc < 3) { fprintf(stderr,"Usage: %s supervisor <base-rootfs>\n",argv[0]); return 1; }
        return run_supervisor(argv[2]);
    }
    if (!strcmp(argv[1], "start"))      return cmd_start(argc, argv);
    if (!strcmp(argv[1], "run"))        return cmd_run(argc, argv);
    if (!strcmp(argv[1], "ps"))         return cmd_ps();
    if (!strcmp(argv[1], "logs"))       return cmd_logs(argc, argv);
    if (!strcmp(argv[1], "stop"))       return cmd_stop(argc, argv);
    usage(argv[0]); return 1;
}

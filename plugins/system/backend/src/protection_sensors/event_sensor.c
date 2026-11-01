/* Native, notify-only Endpoint Security sensor (macOS 11+).
 * No AUTH subscriptions, filesystem reads, arguments, environments, payloads, or network calls.
 * Requires the endpoint-security.client entitlement, root, and Full Disk Access.
 * The callback copies a bounded metadata record and returns; one bounded writer emits JSONL.
 * Two ways to run: `--uid U --home H --exclude-path D` writes to stdout (a terminal capture), or
 * `--serve` (the installed LaunchDaemon) waits on a socket and serves the one user who connects,
 * excluding that user's ~/.cortexterm. A refused client is told why on the socket. When the
 * connection ends the process exits and launchd starts it again.
 */
#define _DARWIN_C_SOURCE 1
#include <EndpointSecurity/EndpointSecurity.h>
#include <bsm/libbsm.h>
#include <dispatch/dispatch.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <pwd.h>
#include <time.h>

#define MAX_PENDING 512
#define SOCKET_PATH "/var/run/ai.cortexterm.event-sensor.sock"
/* Publicly documented EndpointSecurity codesigning_flags CS_VALID bit (also
 * kSecCodeStatusValid in Security/CSCommon.h). No private kernel header dependency. */
#define CT_CS_VALID UINT32_C(0x00000001)
typedef struct {
    uint64_t at, started, started_us;
    pid_t pid, parent;
    int pidversion;
    const char *kind;
    char executable[PATH_MAX], path[PATH_MAX];
} record_t;

static uid_t target_uid;
static char target_home[PATH_MAX], excluded_path[PATH_MAX];
static dispatch_queue_t writer;
static _Atomic uint64_t dropped = 0;
static _Atomic unsigned pending = 0;
static uint64_t last_sequence = 0;
static bool have_sequence = false;
static es_client_t *client = NULL;

static uint64_t now_ms(void) {
    struct timespec t;
    if (clock_gettime(CLOCK_REALTIME, &t) != 0) return 0;
    return (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}

static bool below(const char *path, const char *parent) {
    size_t n = strlen(parent);
    return n > 1 && strncmp(path, parent, n) == 0 && (path[n] == '/' || path[n] == '\0');
}

static bool token_copy(char *out, es_string_token_t value) {
    if (!value.data || value.length == 0 || value.length >= PATH_MAX) return false;
    memcpy(out, value.data, value.length); out[value.length] = '\0';
    /* A path containing NUL/control bytes is not accepted as a different shortened path. */
    for (size_t i = 0; i < value.length; ++i) if ((unsigned char)out[i] < 0x20 || (unsigned char)out[i] == 0x7f) return false;
    return out[0] == '/';
}

static bool file_path(char *out, const es_file_t *file) {
    return file && !file->path_truncated && token_copy(out, file->path);
}

static bool destination(char *out, es_destination_type_t type, const es_file_t *existing, const es_file_t *dir, es_string_token_t name) {
    if (type == ES_DESTINATION_TYPE_EXISTING_FILE) return file_path(out, existing);
    if (type != ES_DESTINATION_TYPE_NEW_PATH || !file_path(out, dir) || !name.data || name.length == 0) return false;
    size_t n = strlen(out);
    if (n + 1 + name.length >= PATH_MAX) return false;
    for (size_t i = 0; i < name.length; ++i) if ((unsigned char)name.data[i] < 0x20 || name.data[i] == '/' || name.data[i] == '\0') return false;
    out[n++] = '/'; memcpy(out + n, name.data, name.length); out[n + name.length] = '\0';
    return true;
}

static bool persistence(const char *path) {
    if (!strncmp(path,"/Library/LaunchAgents/",22) || !strncmp(path,"/Library/LaunchDaemons/",23)) return true;
    if (!below(path,target_home)) return false;
    const char *relative = path + strlen(target_home);
    return !strncmp(relative,"/Library/LaunchAgents/",22) || !strncmp(relative,"/.config/autostart/",19) ||
        !strcmp(relative,"/.zshrc") || !strcmp(relative,"/.zprofile") || !strcmp(relative,"/.bash_profile") ||
        !strcmp(relative,"/.bashrc") || !strcmp(relative,"/.ssh/authorized_keys");
}
static bool credentials(const char *path) {
    if (!below(path,target_home)) return false;
    const char *relative = path + strlen(target_home);
    size_t n = strlen(path);
    bool public_key = n >= 4 && !strcmp(path+n-4,".pub");
    bool browser_store = !strncmp(relative,"/Library/Application Support/",29) || !strncmp(relative,"/Library/Cookies/",17) || !strncmp(relative,"/Library/Containers/",20);
    return !strncmp(relative,"/Library/Keychains/",19) || (!strncmp(relative,"/.ssh/id_",9) && !public_key) ||
        !strcmp(relative,"/.aws/credentials") || !strncmp(relative,"/.config/gcloud/credentials",27) ||
        (browser_store && (strstr(relative,"/Login Data") || strstr(relative,"/Cookies") || strstr(relative,"/logins.json") || strstr(relative,"/key4.db"))) ||
        (n >= 11 && !strcmp(path+n-11,"/wallet.dat"));
}
static bool token_equals(es_string_token_t token, const char *text) {
    return token.data && token.length == strlen(text) && !memcmp(token.data,text,token.length);
}
static bool token_prefix(es_string_token_t token, const char *text) {
    size_t n = strlen(text);
    return token.data && token.length >= n && !memcmp(token.data,text,n);
}
static bool credential_owner(const es_process_t *p, const char *image, const char *path) {
    if (!(p->codesigning_flags & CT_CS_VALID)) return false;
    if (p->is_platform_binary) {
        if (strstr(path,"/Library/Keychains/") &&
            (!strcmp(image,"/usr/sbin/securityd") || !strcmp(image,"/usr/libexec/securityd") || !strcmp(image,"/usr/libexec/secd") || !strcmp(image,"/usr/libexec/trustd"))) return true;
        if (strstr(path,"/.ssh/id_") && !strcmp(image,"/usr/bin/ssh")) return true;
        if ((strstr(path,"/Library/Cookies/") || strstr(path,"/Library/Safari/") || strstr(path,"/com.apple.Safari/")) &&
            (token_equals(p->signing_id,"com.apple.Safari") || token_equals(p->signing_id,"com.apple.WebKit.Networking"))) return true;
    }
    if (strstr(path,"/Google/Chrome/") && token_equals(p->team_id,"EQHXZ8M8AV") && token_prefix(p->signing_id,"com.google.Chrome")) return true;
    if (strstr(path,"/BraveSoftware/Brave-Browser/") && token_equals(p->team_id,"KL8N8XSYF4") && token_prefix(p->signing_id,"com.brave.Browser")) return true;
    if (strstr(path,"/Firefox/") && token_equals(p->team_id,"43AQ936H96") && token_prefix(p->signing_id,"org.mozilla.firefox")) return true;
    if (strstr(path,"/Microsoft Edge/") && token_equals(p->team_id,"UBF8T346G9") && token_prefix(p->signing_id,"com.microsoft.edgemac")) return true;
    return false;
}
static bool archive(const char *path) {
    const char *dot = strrchr(path, '.');
    return dot && (!strcmp(dot,".zip") || !strcmp(dot,".7z") || !strcmp(dot,".tar") || !strcmp(dot,".gz") || !strcmp(dot,".tgz"));
}

static void string_json(const char *text) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)text; *p; ++p) {
        if (*p == '"' || *p == '\\') { putchar('\\'); putchar(*p); }
        else if (*p < 0x20 || *p == 0x7f) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}

static void emit_record(record_t *r) {
    printf("{\"schema\":1,\"record\":\"event\",\"at\":%llu,\"dropped\":%llu,\"observation\":{\"at\":%llu,\"pid\":%d,\"parent_pid\":%d,\"process_started\":%llu,\"process_started_us\":%llu,\"process_version\":%d,\"kind\":",
        (unsigned long long)r->at, (unsigned long long)atomic_load(&dropped), (unsigned long long)r->at, r->pid, r->parent, (unsigned long long)r->started, (unsigned long long)r->started_us, r->pidversion);
    string_json(r->kind); fputs(",\"executable\":",stdout); string_json(r->executable);
    if (r->path[0]) { fputs(",\"path\":",stdout); string_json(r->path); }
    fputs("}}\n",stdout);
    if (fflush(stdout) != 0 || ferror(stdout)) _exit(74);
}

static void handle(const es_message_t *m) {
    if (m->version < 4 || m->action_type != ES_ACTION_TYPE_NOTIFY) { atomic_fetch_add(&dropped, 1); return; }
    if (have_sequence && m->global_seq_num > last_sequence + 1) atomic_fetch_add(&dropped, m->global_seq_num - last_sequence - 1);
    last_sequence = m->global_seq_num; have_sequence = true;
    const es_process_t *p = m->event_type == ES_EVENT_TYPE_NOTIFY_EXEC ? m->event.exec.target : m->process;
    if (!p || audit_token_to_pid(p->audit_token) == getpid() || p->start_time.tv_sec <= 0) return;
    record_t r = {0};
    r.at = (uint64_t)m->time.tv_sec * 1000 + (uint64_t)m->time.tv_nsec / 1000000;
    r.started = (uint64_t)p->start_time.tv_sec;
    r.started_us = r.started * 1000000 + (uint64_t)p->start_time.tv_usec;
    r.pid = audit_token_to_pid(p->audit_token); r.parent = p->ppid;
    r.pidversion = audit_token_to_pidversion(p->audit_token);
    if (!file_path(r.executable, p->executable)) { atomic_fetch_add(&dropped,1); return; }
    bool actor_is_user = audit_token_to_euid(p->audit_token) == target_uid || audit_token_to_ruid(p->audit_token) == target_uid;
    switch (m->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC:
            if (!actor_is_user) return;
            r.kind = "process_exec"; break;
        case ES_EVENT_TYPE_NOTIFY_OPEN:
            if (!file_path(r.path, m->event.open.file) || !below(r.path,target_home) || !credentials(r.path)) return;
            r.kind = credential_owner(p,r.executable,r.path) ? "credential_owner_access" : "credential_access"; break;
        case ES_EVENT_TYPE_NOTIFY_CLOSE:
            if (!m->event.close.modified || !file_path(r.path,m->event.close.target)) return;
            r.kind = "file_write"; break;
        case ES_EVENT_TYPE_NOTIFY_CREATE:
            if (m->event.create.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                if (!file_path(r.path,m->event.create.destination.existing_file)) return;
            } else if (!destination(r.path, m->event.create.destination_type, NULL, m->event.create.destination.new_path.dir, m->event.create.destination.new_path.filename)) return;
            r.kind = "file_write"; break;
        case ES_EVENT_TYPE_NOTIFY_RENAME:
            if (m->event.rename.destination_type == ES_DESTINATION_TYPE_EXISTING_FILE) {
                if (!file_path(r.path,m->event.rename.destination.existing_file)) return;
            } else if (!destination(r.path,m->event.rename.destination_type,NULL,m->event.rename.destination.new_path.dir,m->event.rename.destination.new_path.filename)) return;
            r.kind = "file_rename"; break;
        case ES_EVENT_TYPE_NOTIFY_UNLINK:
            if (!file_path(r.path,m->event.unlink.target)) return;
            r.kind = "file_unlink"; break;
        default: return;
    }
    if (r.path[0]) {
        if (below(r.path, excluded_path)) return;
        bool in_home = below(r.path,target_home);
        bool system_startup = !strncmp(r.path,"/Library/LaunchAgents/",22) || !strncmp(r.path,"/Library/LaunchDaemons/",23);
        bool temporary_archive = actor_is_user && archive(r.path) &&
            (!strncmp(r.path,"/tmp/",5) || !strncmp(r.path,"/private/tmp/",13) ||
             !strncmp(r.path,"/private/var/folders/",21) || !strncmp(r.path,"/var/folders/",13) ||
             !strncmp(r.path,"/Users/Shared/",14));
        if (!in_home && !(actor_is_user && system_startup) && !temporary_archive) return;
        if (strcmp(r.kind,"credential_access") && strcmp(r.kind,"credential_owner_access")) {
            if (persistence(r.path)) r.kind = "persistence_write";
            else if (archive(r.path) && (m->event_type == ES_EVENT_TYPE_NOTIFY_CREATE || m->event_type == ES_EVENT_TYPE_NOTIFY_CLOSE)) r.kind = "archive_created";
        }
        /* Routine browser/app cache churn must not become a bulk user-file alarm. Sensitive
         * credential/persistence/archive observations above remain visible in these locations. */
        if (in_home && (!strcmp(r.kind,"file_write") || !strcmp(r.kind,"file_rename") || !strcmp(r.kind,"file_unlink"))) {
            const char *relative = r.path + strlen(target_home);
            if (!strncmp(relative,"/Library/",9) || !strncmp(relative,"/.cache/",8)) return;
        }
    }
    if (atomic_fetch_add(&pending,1) >= MAX_PENDING) { atomic_fetch_sub(&pending,1); atomic_fetch_add(&dropped,1); return; }
    record_t *copy = malloc(sizeof(*copy));
    if (!copy) { atomic_fetch_sub(&pending,1); atomic_fetch_add(&dropped,1); return; }
    *copy = r;
    dispatch_async(writer, ^{ emit_record(copy); free(copy); atomic_fetch_sub(&pending,1); });
}

static const char *new_client_error(es_new_client_result_t result, bool served) {
    switch (result) {
        case ES_NEW_CLIENT_RESULT_ERR_NOT_ENTITLED: return "Endpoint Security entitlement/provisioning is missing.";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PERMITTED: return served
            ? "Full Disk Access is missing: turn on CortexTermEventSensor in System Settings > Privacy & Security > Full Disk Access."
            : "Full Disk Access permission is missing for the responsible terminal.";
        case ES_NEW_CLIENT_RESULT_ERR_NOT_PRIVILEGED: return "Run only this producer using sudo; the capture sink must remain unprivileged.";
        case ES_NEW_CLIENT_RESULT_ERR_TOO_MANY_CLIENTS: return "macOS has too many Endpoint Security clients.";
        default: return "macOS refused the Endpoint Security client.";
    }
}

/* Tell the client on stdout why the sensor cannot run, then end. */
static int refuse(const char *why, int code) {
    fputs(why,stderr); fputc('\n',stderr);
    printf("{\"schema\":1,\"record\":\"error\",\"at\":%llu,\"text\":",(unsigned long long)now_ms()); string_json(why); fputs("}\n",stdout); fflush(stdout);
    return code;
}

/* The LaunchDaemon: wait for one user's connection; stdout becomes the connection. */
static int serve(void) {
    if (geteuid() != 0) { fputs("The sensor service runs as root (its LaunchDaemon).\n",stderr); return 77; }
    int listener = socket(AF_UNIX,SOCK_STREAM,0);
    if (listener < 0) return 71;
    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strlcpy(address.sun_path,SOCKET_PATH,sizeof(address.sun_path));
    unlink(SOCKET_PATH);
    if (bind(listener,(struct sockaddr *)&address,sizeof(address)) || chmod(SOCKET_PATH,0666) || listen(listener,1)) return 71;
    for (;;) {
        int connection = accept(listener,NULL,NULL);
        if (connection < 0) continue;
        uid_t uid; gid_t gid;
        struct passwd *user = getpeereid(connection,&uid,&gid) == 0 && uid != 0 ? getpwuid(uid) : NULL;
        if (!user || !user->pw_dir || !realpath(user->pw_dir,target_home)) { close(connection); continue; }
        close(listener); unlink(SOCKET_PATH);
        target_uid = uid;
        snprintf(excluded_path,sizeof(excluded_path),"%s/.cortexterm",target_home);
        if (dup2(connection,STDOUT_FILENO) < 0) return 71;
        close(connection);
        return 0;
    }
}

int main(int argc, char **argv) {
    bool served = argc == 2 && !strcmp(argv[1],"--serve");
    if (served) {
        int code = serve();
        if (code) return code;
    } else {
        if (argc != 7 || strcmp(argv[1],"--uid") || strcmp(argv[3],"--home") || strcmp(argv[5],"--exclude-path")) {
            fputs("Usage: cortexterm-event-sensor --serve | --uid UID --home ABSOLUTE_HOME --exclude-path PRIVATE_DATA_DIR\n",stderr); return 64;
        }
        char *end = NULL; errno = 0;
        unsigned long uid = strtoul(argv[2],&end,10);
        if (errno || !end || *end || uid == 0 || uid > UINT32_MAX) return 64;
        target_uid = (uid_t)uid;
        if (geteuid() != 0) { fputs("Native event collection requires root and the Endpoint Security entitlement.\n",stderr); return 77; }
        if (!realpath(argv[4],target_home) || strcmp(argv[4],target_home) || !realpath(argv[6],excluded_path)) return 64;
    }
    struct stat home;
    if (lstat(target_home,&home) || !S_ISDIR(home.st_mode) || home.st_uid != target_uid || !below(excluded_path,target_home)) return refuse("The connected user's home folder could not be verified.",64);
    signal(SIGPIPE,SIG_DFL);
    writer = dispatch_queue_create("ai.cortexterm.security.writer",DISPATCH_QUEUE_SERIAL);
    es_new_client_result_t result = es_new_client(&client, ^(es_client_t *unused, const es_message_t *message) { (void)unused; handle(message); });
    if (result != ES_NEW_CLIENT_RESULT_SUCCESS) return refuse(new_client_error(result, served),77);
    const es_event_type_t events[] = {ES_EVENT_TYPE_NOTIFY_EXEC,ES_EVENT_TYPE_NOTIFY_OPEN,ES_EVENT_TYPE_NOTIFY_CLOSE,ES_EVENT_TYPE_NOTIFY_CREATE,ES_EVENT_TYPE_NOTIFY_RENAME,ES_EVENT_TYPE_NOTIFY_UNLINK};
    if (es_subscribe(client,events,sizeof(events)/sizeof(events[0])) != ES_RETURN_SUCCESS) { es_delete_client(client); return refuse("Cannot subscribe to Endpoint Security notify events.",70); }
    dispatch_source_t heartbeat = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER,0,0,writer);
    dispatch_source_set_timer(heartbeat,dispatch_time(DISPATCH_TIME_NOW,0),5*NSEC_PER_SEC,NSEC_PER_SEC/2);
    dispatch_source_set_event_handler(heartbeat, ^{
        printf("{\"schema\":1,\"record\":\"heartbeat\",\"at\":%llu,\"dropped\":%llu}\n",(unsigned long long)now_ms(),(unsigned long long)atomic_load(&dropped));
        if (fflush(stdout) != 0 || ferror(stdout)) _exit(74);
    });
    dispatch_resume(heartbeat);
    signal(SIGINT,SIG_IGN); signal(SIGTERM,SIG_IGN);
    dispatch_source_t interrupt = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGINT,0,dispatch_get_main_queue());
    dispatch_source_t terminate = dispatch_source_create(DISPATCH_SOURCE_TYPE_SIGNAL,SIGTERM,0,dispatch_get_main_queue());
    void (^stop)(void) = ^{ es_unsubscribe_all(client); es_delete_client(client); dispatch_sync(writer, ^{}); exit(0); };
    dispatch_source_set_event_handler(interrupt,stop); dispatch_source_set_event_handler(terminate,stop);
    dispatch_resume(interrupt); dispatch_resume(terminate);
    dispatch_main();
}

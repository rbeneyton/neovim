/// OS process functions
///
/// psutil is a good reference for cross-platform syscall voodoo:
/// https://github.com/giampaolo/psutil/tree/master/psutil/arch

// IWYU pragma: no_include <sys/param.h>

#include <assert.h>
#include <signal.h>
#include <stdbool.h>
#include <stddef.h>
#include <uv.h>

#ifdef MSWIN
# include <tlhelp32.h>
#endif

#if defined(__FreeBSD__)
# include <string.h>
# include <sys/types.h>
# include <sys/user.h>
#endif

#if defined(__NetBSD__) || defined(__OpenBSD__)
# include <sys/param.h>
#endif

#if defined(__APPLE__) || defined(BSD)
# include <sys/sysctl.h>

# include "nvim/macros_defs.h"
#endif

#if defined(__linux__)
# include <stdio.h>
#endif

#include "nvim/log.h"
#include "nvim/memory.h"
#include "nvim/os/process.h"

#ifdef MSWIN
# include "nvim/api/private/helpers.h"
#endif

#include "nvim/os/shell.h"

#ifdef INCLUDE_GENERATED_DECLARATIONS
# include "os/process.c.generated.h"
#endif

#ifdef MSWIN
static bool os_proc_tree_kill_rec(HANDLE process, int sig)
{
  if (process == NULL) {
    return false;
  }
  PROCESSENTRY32 pe;
  DWORD pid = GetProcessId(process);

  if (pid != 0) {
    HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (h != INVALID_HANDLE_VALUE) {
      pe.dwSize = sizeof(PROCESSENTRY32);
      if (!Process32First(h, &pe)) {
        goto theend;
      }
      do {
        if (pe.th32ParentProcessID == pid) {
          HANDLE ph = OpenProcess(PROCESS_ALL_ACCESS, false, pe.th32ProcessID);
          if (ph != NULL) {
            os_proc_tree_kill_rec(ph, sig);
            CloseHandle(ph);
          }
        }
      } while (Process32Next(h, &pe));
      CloseHandle(h);
    }
  }

theend:
  return (bool)TerminateProcess(process, (unsigned)sig);
}
/// Kills process `pid` and its descendants recursively.
bool os_proc_tree_kill(int pid, int sig)
{
  assert(sig >= 0);
  assert(sig == SIGTERM || sig == SIGKILL);
  if (pid > 0) {
    ILOG("terminating process tree: %d", pid);
    HANDLE h = OpenProcess(PROCESS_ALL_ACCESS, false, (DWORD)pid);
    return os_proc_tree_kill_rec(h, sig);
  } else {
    ELOG("invalid pid: %d", pid);
  }
  return false;
}
#else
/// Kills process group where `pid` is the process group leader.
bool os_proc_tree_kill(int pid, int sig)
{
  assert(sig == SIGTERM || sig == SIGKILL);
  if (pid == 0) {
    // Never kill self (pid=0).
    return false;
  }
  ILOG("sending %s to PID %d", sig == SIGTERM ? "SIGTERM" : "SIGKILL", -pid);
  return uv_kill(-pid, sig) == 0;
}
#endif

/// Gets the process ids of the immediate children of process `ppid`.
///
/// @param ppid Process to inspect.
/// @param[out,allocated] proc_list Child process ids.
/// @param[out] proc_count Number of child processes.
/// @return 0 on success, 1 if process not found, 2 on other error.
int os_proc_children(int ppid, int **proc_list, size_t *proc_count)
  FUNC_ATTR_NONNULL_ALL
{
  if (ppid < 0) {
    return 2;
  }

  int *temp = NULL;
  *proc_list = NULL;
  *proc_count = 0;

#ifdef MSWIN
  PROCESSENTRY32 pe;

  // Snapshot of all processes.
  HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (h == INVALID_HANDLE_VALUE) {
    return 2;
  }

  pe.dwSize = sizeof(PROCESSENTRY32);
  // Get root process.
  if (!Process32First(h, &pe)) {
    CloseHandle(h);
    return 2;
  }
  // Collect processes whose parent matches `ppid`.
  do {
    if (pe.th32ParentProcessID == (DWORD)ppid) {
      temp = xrealloc(temp, (*proc_count + 1) * sizeof(*temp));
      temp[*proc_count] = (int)pe.th32ProcessID;
      (*proc_count)++;
    }
  } while (Process32Next(h, &pe));
  CloseHandle(h);

#elif defined(__APPLE__) || defined(BSD)
# if defined(__APPLE__)
#  define KP_PID(o) o.kp_proc.p_pid
#  define KP_PPID(o) o.kp_eproc.e_ppid
# elif defined(__FreeBSD__)
#  define KP_PID(o) o.ki_pid
#  define KP_PPID(o) o.ki_ppid
# else
#  define KP_PID(o) o.p_pid
#  define KP_PPID(o) o.p_ppid
# endif
# ifdef __NetBSD__
  static int name[] = {
    CTL_KERN, KERN_PROC2, KERN_PROC_ALL, 0, (int)(sizeof(struct kinfo_proc2)), 0
  };
# else
  static int name[] = { CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0 };
# endif

  // Get total process count.
  size_t len = 0;
  int rv = sysctl(name, ARRAY_SIZE(name) - 1, NULL, &len, NULL, 0);
  if (rv) {
    return 2;
  }

  // Get ALL processes.
# ifdef __NetBSD__
  struct kinfo_proc2 *p_list = xmalloc(len);
# else
  struct kinfo_proc *p_list = xmalloc(len);
# endif
  rv = sysctl(name, ARRAY_SIZE(name) - 1, p_list, &len, NULL, 0);
  if (rv) {
    xfree(p_list);
    return 2;
  }

  // Collect processes whose parent matches `ppid`.
  bool exists = false;
  size_t p_count = len / sizeof(*p_list);
  for (size_t i = 0; i < p_count; i++) {
    exists = exists || KP_PID(p_list[i]) == ppid;
    if (KP_PPID(p_list[i]) == ppid) {
      temp = xrealloc(temp, (*proc_count + 1) * sizeof(*temp));
      temp[*proc_count] = KP_PID(p_list[i]);
      (*proc_count)++;
    }
  }
  xfree(p_list);
  if (!exists) {
    return 1;  // Process not found.
  }

#elif defined(__linux__)
  char proc_p[256] = { 0 };
  // Collect processes whose parent matches `ppid`.
  // Rationale: children are defined in thread with same ID of process.
  snprintf(proc_p, sizeof(proc_p), "/proc/%d/task/%d/children", ppid, ppid);
  FILE *fp = fopen(proc_p, "r");
  if (fp == NULL) {
    return 2;  // Process not found, or /proc/…/children not supported.
  }
  int match_pid;
  while (fscanf(fp, "%d", &match_pid) > 0) {
    temp = xrealloc(temp, (*proc_count + 1) * sizeof(*temp));
    temp[*proc_count] = match_pid;
    (*proc_count)++;
  }
  fclose(fp);
#endif

  *proc_list = temp;
  return 0;
}

#ifdef MSWIN
/// Gets various properties of the process identified by `pid`.
///
/// @param pid Process to inspect.
/// @return Map of process properties, empty on error.
Dictionary os_proc_info(int pid)
{
  Dictionary pinfo = ARRAY_DICT_INIT;
  PROCESSENTRY32 pe;

  // Snapshot of all processes.  This is used instead of:
  //    OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, …)
  // to avoid ERROR_PARTIAL_COPY.  https://stackoverflow.com/a/29942376
  HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (h == INVALID_HANDLE_VALUE) {
    return pinfo;  // Return empty.
  }

  pe.dwSize = sizeof(PROCESSENTRY32);
  // Get root process.
  if (!Process32First(h, &pe)) {
    CloseHandle(h);
    return pinfo;  // Return empty.
  }
  // Find the process.
  do {
    if (pe.th32ProcessID == (DWORD)pid) {
      break;
    }
  } while (Process32Next(h, &pe));
  CloseHandle(h);

  if (pe.th32ProcessID == (DWORD)pid) {
    PUT(pinfo, "pid", INTEGER_OBJ(pid));
    PUT(pinfo, "ppid", INTEGER_OBJ((int)pe.th32ParentProcessID));
    PUT(pinfo, "name", CSTR_TO_OBJ(pe.szExeFile));
  }

  return pinfo;
}
#endif

/// Return true if process `pid` is running.
bool os_proc_running(int pid)
{
  int err = uv_kill(pid, 0);
  // If there is no error the process must be running.
  if (err == 0) {
    return true;
  }
  // If the error is ESRCH then the process is not running.
  if (err == UV_ESRCH) {
    return false;
  }
  // If the process is running and owned by another user we get EPERM.  With
  // other errors the process might be running, assuming it is then.
  return true;
}

#if defined(__linux__)
/// Fill given buffer with potential tmux specific information about the pid
bool os_proc_tmux_info(int pid, char msg[static 512])
{
  FILE *fp = NULL;
  char *buf = NULL;
  char **argv = NULL;
  const size_t narg = 13;
  char *tmux_call_output = NULL;

  char proc_env[256] = { 0 };
  if (snprintf(proc_env, sizeof(proc_env), "/proc/%d/environ", pid)
      >= (long)sizeof(proc_env))
  {
    return false;
  }

  // sanity checks
  struct stat statbuf;
  if (stat(proc_env, &statbuf) < 0) {
    return false; // no process any more or no /proc filesystem
  }
  if (statbuf.st_size != 0
  || (statbuf.st_mode & S_IFMT) != S_IFREG)
  {
    return false; // unusual /proc filesystem
  }

  // read environ file
  fp = fopen(proc_env, "r");
  if (fp == NULL) return false;
  size_t buf_sz = 1;
  size_t sz = 0;
  const size_t step = 1UL << 10;
  while (true) {
    if (buf_sz < sz + step + 1) {
      buf_sz += step;
      char *p = xrealloc(buf, buf_sz);
      if (p == NULL) goto error;
      buf = p;
    }
    const size_t read = fread(buf + sz, 1, step, fp);
    if (read == 0) {
      if (feof(fp)) break;
      if (ferror(fp)) goto error;
    }
    sz += read;
    assert (sz < buf_sz);
    buf[sz] = '\0'; // fread is \0 string unsafe
  }
  fclose(fp);
  fp = NULL;

  // scan each token and extract tmux related fields
  char *p = buf;
  const char *p_end = buf + sz;
  assert (*p_end == '\0');
  char *tok;
  char pane_id[256] = { 0 };
  char socket_path[256] = { 0 };
  int server_pid = 0;

  while ((tok = memchr(p, '\0', (size_t)(p_end - p)))) {
    const char *eq = memchr(p, '=', (size_t)(tok - p));
    if (eq != NULL) {
      eq++;
      const size_t tok_len = (size_t)(eq - p);

      if (strncmp(p, "TMUX_PANE=", tok_len) == 0) {
        if (sscanf(eq, "%255s", pane_id) != 1
        ||  strlen(pane_id) == 0)
        {
          goto error;
        }
      }

      if (strncmp(p, "TMUX=", tok_len) == 0) {
        // format (undocumented): socket-path,server-pid,...
        if (sscanf(eq, "%255[^,],%d,", socket_path, &server_pid) != 2
        ||  strlen(socket_path) == 0
        ||  server_pid == 0
        ||  !os_proc_running(server_pid))
        {
          goto error;
        }
      }
    }
    if (tok == p_end) break;
    p = tok + 1;
  }
  xfree(buf);
  buf = NULL;

  // extract pane information using tmux CLI
  argv = xmalloc(sizeof(char*) * narg);
  if (argv == NULL) goto error;
  memset(argv, 0, sizeof(char*) * narg);

  const size_t warg = 256;
  for (size_t i = 0; i < narg; i++) {
      argv[i] = xmalloc(warg);
      if (argv[i] == NULL) goto error;
  }
  size_t idx = 0;
#define ADD_ARG(...)                                                         \
  if (snprintf(argv[idx++], warg, __VA_ARGS__) >= (long)warg) {              \
      goto error;                                                            \
  }

  // robust against freezed tmux server (rare infinite loop bug)
  ADD_ARG("/usr/bin/timeout");
  ADD_ARG("--kill-after=1");
  ADD_ARG("1s");
  // use current running server binary to avoid calling random 'tmux' program
  ADD_ARG("/proc/%d/exe", server_pid);
  // select corresponding server
  ADD_ARG("-S");
  ADD_ARG("%s", socket_path);
  ADD_ARG("list-panes");
  // report format "sesion:<session> pane:<id>(<title>) win:<id>"
  ADD_ARG("-F");
  ADD_ARG("session `#{session_name}` pane `#{window_index}(#{window_name}).#{pane_index}`");
  // filter to get corresponding pane_id
  ADD_ARG("-f");
  ADD_ARG("#{==:#{pane_id},%s}", pane_id);
  ADD_ARG("-a");
#undef ADD_ARG
  argv[idx++] = NULL;
  assert (idx == narg);

  if (os_system(argv, NULL, 0, &tmux_call_output, NULL) < 0
  ||  tmux_call_output == NULL)
  {
    argv = NULL; // argv memory ownership given to os_system() so no leak here
    goto error;
  }
  char *tr = strchr(tmux_call_output, '\n');
  if (tr != NULL) *tr = '\0';
  const bool res = snprintf(msg, 512, "%s", tmux_call_output) < 512;
  xfree(tmux_call_output);

  return res;

error:
  if (fp != NULL) fclose(fp);
  xfree(buf);
  if (argv) {
    for (size_t i = 0; i < narg; i++) xfree(argv[i]);
    xfree(argv);
  }
  xfree(tmux_call_output);

  return false;
}
#endif

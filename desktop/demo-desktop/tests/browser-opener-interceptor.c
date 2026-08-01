#include <errno.h>
#include <fcntl.h>
#include <spawn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static const char *authorization_url(char *const argv[]) {
  if (argv == NULL) {
    return NULL;
  }
  for (size_t index = 0; argv[index] != NULL; index += 1) {
    if (strncmp(argv[index], "http://", 7) == 0 ||
        strncmp(argv[index], "https://", 8) == 0) {
      return argv[index];
    }
  }
  return NULL;
}

static int explicitly_selects_application(char *const argv[]) {
  if (argv == NULL) {
    return 0;
  }
  for (size_t index = 1; argv[index] != NULL; index += 1) {
    if (strcmp(argv[index], "-a") == 0 || strcmp(argv[index], "-b") == 0) {
      return 1;
    }
  }
  return 0;
}

static int capture_if_target(const char *path, char *const argv[]) {
  const char *target = getenv("UNIFIED_LOGIN_INTERCEPT_EXECUTABLE");
  if (target == NULL || path == NULL || strcmp(path, target) != 0) {
    return 0;
  }

  const char *url = authorization_url(argv);
  if (url == NULL) {
    return 0;
  }
  if (explicitly_selects_application(argv)) {
    errno = EINVAL;
    return -1;
  }

  const char *capture_path = getenv("UNIFIED_LOGIN_BROWSER_URL_FILE");
  if (capture_path == NULL) {
    errno = EINVAL;
    return -1;
  }

  int file = open(capture_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
  if (file == -1) {
    return -1;
  }

  size_t remaining = strlen(url);
  const char *cursor = url;
  while (remaining > 0) {
    ssize_t written = write(file, cursor, remaining);
    if (written <= 0) {
      int write_error = errno;
      close(file);
      errno = write_error;
      return -1;
    }
    cursor += written;
    remaining -= (size_t)written;
  }

  if (close(file) == -1) {
    return -1;
  }
  return 1;
}

static int intercepted_execve(const char *path, char *const argv[],
                              char *const envp[]) {
  int capture = capture_if_target(path, argv);
  if (capture == -1) {
    return -1;
  }
  if (capture == 1) {
    char *const true_argv[] = {"true", NULL};
    return execve("/usr/bin/true", true_argv, envp);
  }
  return execve(path, argv, envp);
}

static int intercepted_execv(const char *path, char *const argv[]) {
  int capture = capture_if_target(path, argv);
  if (capture == -1) {
    return -1;
  }
  if (capture == 1) {
    char *const true_argv[] = {"true", NULL};
    return execv("/usr/bin/true", true_argv);
  }
  return execv(path, argv);
}

static int intercepted_execvp(const char *path, char *const argv[]) {
  int capture = capture_if_target(path, argv);
  if (capture == -1) {
    return -1;
  }
  if (capture == 1) {
    char *const true_argv[] = {"true", NULL};
    return execvp("/usr/bin/true", true_argv);
  }
  return execvp(path, argv);
}

static int intercepted_posix_spawn(
    pid_t *pid, const char *path,
    const posix_spawn_file_actions_t *file_actions,
    const posix_spawnattr_t *attributes, char *const argv[],
    char *const envp[]) {
  int capture = capture_if_target(path, argv);
  if (capture == -1) {
    return errno;
  }
  if (capture == 1) {
    char *const true_argv[] = {"true", NULL};
    return posix_spawn(pid, "/usr/bin/true", file_actions, attributes,
                       true_argv, envp);
  }
  return posix_spawn(pid, path, file_actions, attributes, argv, envp);
}

#define DYLD_INTERPOSE(replacement, replacee)                                \
  __attribute__((used)) static struct {                                      \
    const void *replacement_function;                                        \
    const void *replacee_function;                                           \
  } interpose_##replacee __attribute__((section("__DATA,__interpose"))) = {  \
      (const void *)(unsigned long)&replacement,                              \
      (const void *)(unsigned long)&replacee};

DYLD_INTERPOSE(intercepted_execve, execve)
DYLD_INTERPOSE(intercepted_execv, execv)
DYLD_INTERPOSE(intercepted_execvp, execvp)
DYLD_INTERPOSE(intercepted_posix_spawn, posix_spawn)

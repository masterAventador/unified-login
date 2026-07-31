#include <spawn.h>
#include <stdio.h>
#include <sys/wait.h>

extern char **environ;

int main(int argc, char *argv[]) {
  if (argc < 2) {
    return 2;
  }

  pid_t child;
  int spawn_error =
      posix_spawn(&child, argv[1], NULL, NULL, &argv[1], environ);
  if (spawn_error != 0) {
    return 3;
  }

  int status;
  if (waitpid(child, &status, 0) == -1) {
    return 4;
  }
  if (!WIFEXITED(status)) {
    return 5;
  }
  return WEXITSTATUS(status);
}

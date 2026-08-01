#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

__attribute__((constructor)) static void delay_application_startup(void) {
  const char *marker_path = getenv("UNIFIED_LOGIN_DELAYED_APP_PID_FILE");
  if (marker_path != NULL) {
    int descriptor =
        open(marker_path, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (descriptor >= 0) {
      dprintf(descriptor, "%d\n", getpid());
      close(descriptor);
    }
  }
  usleep(1000000);
}

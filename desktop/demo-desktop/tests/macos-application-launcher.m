#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

#include <signal.h>

static volatile sig_atomic_t launched_process_id = -1;
static volatile sig_atomic_t requested_termination_signal = 0;

static void print_error(NSString *message) {
  fprintf(stderr, "%s\n", message.UTF8String);
}

static void request_launched_application_termination(int signal_number) {
  if (requested_termination_signal == 0) {
    requested_termination_signal = signal_number;
  }
  if (launched_process_id > 1) {
    kill((pid_t)launched_process_id, SIGTERM);
  }
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    if (argc < 2) {
      print_error(@"缺少要启动的 app bundle");
      return 64;
    }

    NSString *artifact =
        [[NSFileManager defaultManager]
            stringWithFileSystemRepresentation:argv[1]
                                        length:strlen(argv[1])];
    NSURL *application_url = [NSURL fileURLWithPath:artifact];
    NSMutableDictionary<NSString *, NSString *> *environment =
        [NSProcessInfo.processInfo.environment mutableCopy];
    for (int index = 2; index < argc; index += 1) {
      NSString *entry = [NSString stringWithUTF8String:argv[index]];
      NSRange separator = [entry rangeOfString:@"="];
      if (separator.location == NSNotFound || separator.location == 0) {
        print_error(@"应用环境变量参数无效");
        return 64;
      }
      NSString *name = [entry substringToIndex:separator.location];
      NSString *value =
          [entry substringFromIndex:separator.location + separator.length];
      environment[name] = value;
    }

    signal(SIGINT, request_launched_application_termination);
    signal(SIGTERM, request_launched_application_termination);

    NSWorkspaceOpenConfiguration *configuration =
        [NSWorkspaceOpenConfiguration configuration];
    configuration.activates = NO;
    configuration.addsToRecentItems = NO;
    configuration.createsNewApplicationInstance = YES;
    configuration.promptsUserIfNeeded = NO;
    configuration.environment = environment;

    __block NSRunningApplication *application = nil;
    __block NSError *launch_error = nil;
    __block BOOL completed = NO;
    [[NSWorkspace sharedWorkspace]
        openApplicationAtURL:application_url
               configuration:configuration
           completionHandler:^(NSRunningApplication *running_application,
                               NSError *error) {
             application = running_application;
             launch_error = error;
             completed = YES;
           }];

    NSRunLoop *run_loop = NSRunLoop.currentRunLoop;
    while (!completed) {
      [run_loop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }
    if (application == nil) {
      if (requested_termination_signal != 0) {
        return 128 + requested_termination_signal;
      }
      print_error(launch_error.localizedDescription ?: @"LaunchServices 启动失败");
      return 1;
    }

    launched_process_id = application.processIdentifier;
    if (requested_termination_signal != 0) {
      kill((pid_t)launched_process_id, SIGTERM);
      while (!application.terminated) {
        [run_loop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
      }
      return 128 + requested_termination_signal;
    }
    printf("%d\n", application.processIdentifier);
    fflush(stdout);
    while (!application.terminated) {
      [run_loop runUntilDate:[NSDate dateWithTimeIntervalSinceNow:0.05]];
    }
    return requested_termination_signal == 0
               ? 0
               : 128 + requested_termination_signal;
  }
}

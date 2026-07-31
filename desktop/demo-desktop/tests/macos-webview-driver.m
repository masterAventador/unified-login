#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>
#import <WebKit/WebKit.h>

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

static const NSUInteger MAX_REQUEST_BYTES = 1024 * 1024;
static const int DRIVER_TIMEOUT_SECONDS = 20;

static WKWebView *find_webview_in_view(NSView *view) {
  if ([view isKindOfClass:[WKWebView class]]) {
    return (WKWebView *)view;
  }
  for (NSView *subview in view.subviews) {
    WKWebView *candidate = find_webview_in_view(subview);
    if (candidate != nil) {
      return candidate;
    }
  }
  return nil;
}

static WKWebView *find_webview(void) {
  for (NSWindow *window in NSApp.windows) {
    WKWebView *candidate = find_webview_in_view(window.contentView);
    if (candidate != nil) {
      return candidate;
    }
  }
  return nil;
}

static NSDictionary *error_response(NSString *message) {
  return @{@"ok" : @NO, @"error" : message};
}

static NSDictionary *evaluate_request(NSDictionary *request,
                                      NSString *expected_token) {
  if (![request[@"token"] isKindOfClass:[NSString class]] ||
      ![request[@"token"] isEqualToString:expected_token]) {
    return error_response(@"unauthorized");
  }
  if ([request[@"command"] isEqualToString:@"terminate"]) {
    dispatch_after(
        dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.1 * NSEC_PER_SEC)),
        dispatch_get_main_queue(), ^{
          [NSApp terminate:nil];
        });
    return @{@"ok" : @YES, @"value" : [NSNull null]};
  }
  NSString *script = request[@"script"];
  if (![script isKindOfClass:[NSString class]] || script.length == 0) {
    return error_response(@"invalid script");
  }

  dispatch_semaphore_t completed = dispatch_semaphore_create(0);
  __block NSDictionary *response = nil;
  dispatch_async(dispatch_get_main_queue(), ^{
    WKWebView *webview = find_webview();
    if (webview == nil) {
      response = error_response(@"webview unavailable");
      dispatch_semaphore_signal(completed);
      return;
    }
    [webview evaluateJavaScript:script
             completionHandler:^(id value, NSError *error) {
               if (error != nil) {
                 response = error_response(error.localizedDescription);
               } else {
                 response = @{
                   @"ok" : @YES,
                   @"value" : value == nil ? [NSNull null] : value
                 };
               }
               dispatch_semaphore_signal(completed);
             }];
  });

  dispatch_time_t timeout =
      dispatch_time(DISPATCH_TIME_NOW,
                    (int64_t)DRIVER_TIMEOUT_SECONDS * NSEC_PER_SEC);
  if (dispatch_semaphore_wait(completed, timeout) != 0) {
    return error_response(@"evaluation timed out");
  }
  return response;
}

static NSData *read_request(int client) {
  NSMutableData *data = [NSMutableData data];
  char buffer[4096];
  while (data.length < MAX_REQUEST_BYTES) {
    ssize_t count = read(client, buffer, sizeof(buffer));
    if (count <= 0) {
      return nil;
    }
    const char *newline = memchr(buffer, '\n', (size_t)count);
    NSUInteger accepted =
        newline == NULL ? (NSUInteger)count : (NSUInteger)(newline - buffer);
    [data appendBytes:buffer length:accepted];
    if (newline != NULL) {
      return data;
    }
  }
  return nil;
}

static void write_response(int client, NSDictionary *response) {
  NSError *error = nil;
  NSData *json = [NSJSONSerialization dataWithJSONObject:response
                                                 options:0
                                                   error:&error];
  if (json == nil) {
    json = [NSJSONSerialization
        dataWithJSONObject:error_response(@"response is not JSON serializable")
                   options:0
                     error:nil];
  }
  NSMutableData *payload = [json mutableCopy];
  [payload appendBytes:"\n" length:1];

  const uint8_t *cursor = payload.bytes;
  NSUInteger remaining = payload.length;
  while (remaining > 0) {
    ssize_t written = write(client, cursor, remaining);
    if (written <= 0) {
      return;
    }
    cursor += written;
    remaining -= (NSUInteger)written;
  }
}

static void serve_client(int client, NSString *expected_token) {
  @autoreleasepool {
    NSData *payload = read_request(client);
    if (payload == nil) {
      write_response(client, error_response(@"invalid request"));
      return;
    }
    NSError *error = nil;
    id request = [NSJSONSerialization JSONObjectWithData:payload
                                                 options:0
                                                   error:&error];
    if (![request isKindOfClass:[NSDictionary class]]) {
      write_response(client, error_response(@"invalid JSON"));
      return;
    }
    write_response(client, evaluate_request(request, expected_token));
  }
}

static void run_server(uint16_t port, NSString *expected_token) {
  int server = socket(AF_INET, SOCK_STREAM, 0);
  if (server == -1) {
    return;
  }
  int reuse = 1;
  setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));

  struct sockaddr_in address = {
      .sin_len = sizeof(address),
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = {.s_addr = htonl(INADDR_LOOPBACK)},
  };
  if (bind(server, (struct sockaddr *)&address, sizeof(address)) == -1 ||
      listen(server, 4) == -1) {
    close(server);
    return;
  }

  while (true) {
    int client = accept(server, NULL, NULL);
    if (client == -1) {
      if (errno == EINTR) {
        continue;
      }
      break;
    }
    serve_client(client, expected_token);
    close(client);
  }
  close(server);
}

__attribute__((constructor)) static void start_webview_driver(void) {
  @autoreleasepool {
    NSDictionary<NSString *, NSString *> *environment =
        NSProcessInfo.processInfo.environment;
    NSString *expected_executable =
        environment[@"UNIFIED_LOGIN_WEBVIEW_DRIVER_EXECUTABLE"];
    if (expected_executable.length == 0 ||
        ![NSProcessInfo.processInfo.processName
            isEqualToString:expected_executable]) {
      return;
    }
    NSString *port_value =
        environment[@"UNIFIED_LOGIN_WEBVIEW_DRIVER_PORT"];
    NSString *token = environment[@"UNIFIED_LOGIN_WEBVIEW_DRIVER_TOKEN"];
    NSInteger port = port_value.integerValue;
    if (port < 1 || port > UINT16_MAX || token.length < 32) {
      return;
    }

    dispatch_async(
        dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0),
        ^{
          run_server((uint16_t)port, token);
        });
  }
}

#import <AppKit/AppKit.h>
#import <Foundation/Foundation.h>

int main(void) {
  @autoreleasepool {
    NSApplication *application = [NSApplication sharedApplication];
    [application setActivationPolicy:NSApplicationActivationPolicyProhibited];
    [application run];
    return 0;
  }
}

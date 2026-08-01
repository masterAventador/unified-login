#import <AppKit/AppKit.h>
#import <WebKit/WebKit.h>

int main(void) {
  @autoreleasepool {
    [NSApplication sharedApplication];
    NSWindow *window =
        [[NSWindow alloc] initWithContentRect:NSMakeRect(0, 0, 320, 200)
                                   styleMask:NSWindowStyleMaskBorderless
                                     backing:NSBackingStoreBuffered
                                       defer:NO];
    WKWebView *webview = [[WKWebView alloc] initWithFrame:window.contentView.bounds];
    window.contentView = webview;
    [webview
        loadHTMLString:
            @"<!doctype html>"
             "<style>"
             "#action,#covered,#cover{position:absolute;left:10px;width:100px;height:30px}"
             "#action{top:10px}#covered,#cover{top:60px}#cover{z-index:2}"
             "</style>"
             "<button id='action'>ready</button>"
             "<button id='covered'>covered</button>"
             "<div id='cover'></div>"
             "<script>"
             "action.addEventListener('click',()=>action.dataset.clicked='yes')"
             "</script>"
                 baseURL:nil];
    [NSApp run];
  }
  return 0;
}

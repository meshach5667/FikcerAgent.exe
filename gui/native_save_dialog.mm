#import <AppKit/AppKit.h>

#include "gui/native_save_dialog.h"

namespace fikcer::gui {

std::optional<std::filesystem::path> chooseNativeSavePath(
    const std::string& title,
    const std::string& defaultFileName,
    const std::string& allowedExtension)
{
    @autoreleasepool {
        NSSavePanel* panel = [NSSavePanel savePanel];
        [panel setCanCreateDirectories:YES];
        [panel setTitle:[NSString stringWithUTF8String:title.c_str()]];
        [panel setNameFieldStringValue:[NSString stringWithUTF8String:defaultFileName.c_str()]];

        if (!allowedExtension.empty()) {
            [panel setAllowedFileTypes:@[[NSString stringWithUTF8String:allowedExtension.c_str()]]];
        }

        NSModalResponse response = [panel runModal];
        if (response != NSModalResponseOK) {
            return std::nullopt;
        }

        NSURL* url = [panel URL];
        if (!url) {
            return std::nullopt;
        }

        std::string path([[url path] UTF8String]);
        return std::filesystem::path(path);
    }
}

} // namespace fikcer::gui
// ============================================================================
// FikcerAgent – System Notification Utility
// ============================================================================
// Sends native OS notifications so the user is alerted to critical issues
// and auto-fix actions even when the FikcerAgent window is in the background.
//
//   • macOS  : osascript (AppleScript display notification)
//   • Windows: PowerShell toast notification
// ============================================================================
#pragma once

#include <string>
#include <cstdlib>

namespace fikcer::utils {

/// Send a native OS notification.
/// @param title    Main notification title (e.g. "FikcerAgent").
/// @param message  Body text.
/// @param subtitle Optional subtitle line.
inline void sendNotification(const std::string& title,
                              const std::string& message,
                              const std::string& subtitle = "") {
    // Escape double-quotes for shell safety.
    auto escape = [](const std::string& s) -> std::string {
        std::string r;
        r.reserve(s.size());
        for (char c : s) {
            if (c == '"' || c == '\\') r += '\\';
            r += c;
        }
        return r;
    };

#ifdef __APPLE__
    std::string cmd = "osascript -e 'display notification \"" +
                      escape(message) + "\" with title \"" +
                      escape(title) + "\"";
    if (!subtitle.empty()) {
        cmd += " subtitle \"" + escape(subtitle) + "\"";
    }
    cmd += " sound name \"Submarine\"' >/dev/null 2>&1 &";
    std::system(cmd.c_str());

#elif defined(_WIN32)
    // Minimal Windows toast via PowerShell (works on Win 10+).
    std::string ps =
        "powershell -WindowStyle Hidden -Command \""
        "Add-Type -AssemblyName System.Windows.Forms; "
        "$n = New-Object System.Windows.Forms.NotifyIcon; "
        "$n.Icon = [System.Drawing.SystemIcons]::Information; "
        "$n.Visible = $true; "
        "$n.ShowBalloonTip(5000, '" + escape(title) + "', '" +
        escape(message) + "', 'Info'); "
        "Start-Sleep -Seconds 6; $n.Dispose()\" >NUL 2>&1";
    std::system(ps.c_str());
#endif
}

} // namespace fikcer::utils

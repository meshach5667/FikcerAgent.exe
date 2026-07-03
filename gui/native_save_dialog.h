#pragma once

#include <filesystem>
#include <optional>
#include <string>

namespace fikcer::gui {

[[nodiscard]] std::optional<std::filesystem::path> chooseNativeSavePath(
    const std::string& title,
    const std::string& defaultFileName,
    const std::string& allowedExtension);

} // namespace fikcer::gui
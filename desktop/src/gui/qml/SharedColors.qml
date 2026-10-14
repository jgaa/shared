pragma Singleton
import QtQuick

QtObject {
    function luminance(color) {
        function linear(value) {
            return value <= 0.04045 ? value / 12.92 : Math.pow((value + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * linear(color.r) + 0.7152 * linear(color.g) + 0.0722 * linear(color.b)
    }

    function contrast(foreground, background) {
        const first = luminance(foreground)
        const second = luminance(background)
        return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05)
    }

    // Preserve status hues where readable; otherwise adapt them to the surface.
    function statusColor(value, background, textColor) {
        const original = Qt.darker(value, 1)
        if (contrast(original, background) >= 4.5)
            return original
        const adjusted = luminance(background) < 0.5
            ? Qt.lighter(original, 1.8) : Qt.darker(original, 1.8)
        return contrast(adjusted, background) >= 4.5 ? adjusted : textColor
    }
}

import AppKit
// make-icon <repository root> [dev]: draws the app icon into native/work/AppIcon.iconset, or with "dev" the orange
// Shipshape Dev icon into native/work/AppIcon-Dev.iconset, so a development copy is easy to tell apart. The ship is
// ShipMark, the logo the app draws too, so build this with native/Sources/ShipMark.swift:
//   xcrun swiftc -parse-as-library native/make-icon.swift native/Sources/ShipMark.swift -o native/work/make-icon
// then turn the iconset into native/Resources/AppIcon.icns with iconutil -c icns.
@main struct MakeIcon {
    static func main() throws {
        let root = URL(fileURLWithPath: CommandLine.arguments[1])
        let dev = CommandLine.arguments.count > 2 && CommandLine.arguments[2] == "dev"
        let iconset = root.appendingPathComponent(dev ? "native/work/AppIcon-Dev.iconset" : "native/work/AppIcon.iconset")
        // The released icon is black, a little lighter at the top; the development copy's is orange.
        let colors = dev ? (NSColor(calibratedRed: 0.55, green: 0.20, blue: 0.04, alpha: 1), NSColor(calibratedRed: 0.93, green: 0.49, blue: 0.13, alpha: 1))
                         : (NSColor(calibratedWhite: 0.0, alpha: 1), NSColor(calibratedWhite: 0.17, alpha: 1))
        try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
        for size in [16, 32, 128, 256, 512] {
            for scale in [1, 2] {
                let pixels = size * scale
                let image = NSImage(size: NSSize(width: pixels, height: pixels))
                image.lockFocus()
                let factor = CGFloat(pixels) / 1024
                let transform = NSAffineTransform(); transform.scale(by: factor); transform.concat()
                let background = NSBezierPath(roundedRect: NSRect(x: 78, y: 78, width: 868, height: 868), xRadius: 190, yRadius: 190)
                NSGradient(starting: colors.0, ending: colors.1)!.draw(in: background, angle: 90)
                ShipMark.draw(in: NSGraphicsContext.current!.cgContext, fitting: ShipMark.box, color: NSColor.white.withAlphaComponent(0.96).cgColor)
                image.unlockFocus()
                let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
                let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
                try bitmap.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent(name))
            }
        }
    }
}

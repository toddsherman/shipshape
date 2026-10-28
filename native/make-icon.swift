import AppKit
// make-icon <repository root> [dev]: draws the app icon into native/work/AppIcon.iconset, or with "dev" the orange
// Shipshape Dev icon into native/work/AppIcon-Dev.iconset, so a development copy is easy to tell apart.
let root = URL(fileURLWithPath: CommandLine.arguments[1])
let dev = CommandLine.arguments.count > 2 && CommandLine.arguments[2] == "dev"
let iconset = root.appendingPathComponent(dev ? "native/work/AppIcon-Dev.iconset" : "native/work/AppIcon.iconset")
let colors = dev ? (NSColor(calibratedRed: 0.55, green: 0.20, blue: 0.04, alpha: 1), NSColor(calibratedRed: 0.93, green: 0.49, blue: 0.13, alpha: 1))
                 : (NSColor(calibratedRed: 0.09, green: 0.25, blue: 0.33, alpha: 1), NSColor(calibratedRed: 0.16, green: 0.44, blue: 0.48, alpha: 1))
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
        // A sailboat: hull, mast, mainsail and jib, over a line of waves.
        NSColor.white.withAlphaComponent(0.96).setFill(); NSColor.white.withAlphaComponent(0.96).setStroke()
        let hull = NSBezierPath()
        hull.move(to: NSPoint(x: 236, y: 400)); hull.line(to: NSPoint(x: 788, y: 400))
        hull.curve(to: NSPoint(x: 690, y: 282), controlPoint1: NSPoint(x: 760, y: 340), controlPoint2: NSPoint(x: 730, y: 296))
        hull.line(to: NSPoint(x: 334, y: 282))
        hull.curve(to: NSPoint(x: 236, y: 400), controlPoint1: NSPoint(x: 294, y: 296), controlPoint2: NSPoint(x: 264, y: 340))
        hull.close(); hull.fill()
        let mast = NSBezierPath(); mast.move(to: NSPoint(x: 512, y: 410)); mast.line(to: NSPoint(x: 512, y: 812)); mast.lineWidth = 26; mast.lineCapStyle = .round; mast.stroke()
        let mainsail = NSBezierPath()
        mainsail.move(to: NSPoint(x: 488, y: 790))
        mainsail.curve(to: NSPoint(x: 282, y: 446), controlPoint1: NSPoint(x: 390, y: 695), controlPoint2: NSPoint(x: 320, y: 578))
        mainsail.line(to: NSPoint(x: 488, y: 446)); mainsail.close(); mainsail.fill()
        let jib = NSBezierPath()
        jib.move(to: NSPoint(x: 536, y: 744))
        jib.curve(to: NSPoint(x: 712, y: 446), controlPoint1: NSPoint(x: 620, y: 661), controlPoint2: NSPoint(x: 680, y: 559))
        jib.line(to: NSPoint(x: 536, y: 446)); jib.close(); jib.fill()
        let waves = NSBezierPath(); waves.move(to: NSPoint(x: 262, y: 214))
        for crest in 0..<4 {
            let x = 262 + CGFloat(crest) * 125
            waves.curve(to: NSPoint(x: x + 125, y: 214), controlPoint1: NSPoint(x: x + 40, y: 254), controlPoint2: NSPoint(x: x + 85, y: 174))
        }
        NSColor.white.withAlphaComponent(0.6).setStroke(); waves.lineWidth = 28; waves.lineCapStyle = .round; waves.stroke()
        image.unlockFocus()
        let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
        let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent(name))
    }
}

import AppKit
let root = URL(fileURLWithPath: CommandLine.arguments[1])
let iconset = root.appendingPathComponent("native/work/AppIcon.iconset")
try FileManager.default.createDirectory(at: iconset, withIntermediateDirectories: true)
for size in [16, 32, 128, 256, 512] {
    for scale in [1, 2] {
        let pixels = size * scale
        let image = NSImage(size: NSSize(width: pixels, height: pixels))
        image.lockFocus()
        let factor = CGFloat(pixels) / 1024
        let transform = NSAffineTransform(); transform.scale(by: factor); transform.concat()
        let background = NSBezierPath(roundedRect: NSRect(x: 78, y: 78, width: 868, height: 868), xRadius: 190, yRadius: 190)
        NSGradient(starting: NSColor(calibratedRed: 0.09, green: 0.25, blue: 0.33, alpha: 1), ending: NSColor(calibratedRed: 0.16, green: 0.44, blue: 0.48, alpha: 1))!.draw(in: background, angle: 90)
        let shield = NSBezierPath()
        shield.move(to: NSPoint(x: 512, y: 790))
        shield.curve(to: NSPoint(x: 735, y: 705), controlPoint1: NSPoint(x: 590, y: 748), controlPoint2: NSPoint(x: 668, y: 720))
        shield.line(to: NSPoint(x: 735, y: 530))
        shield.curve(to: NSPoint(x: 512, y: 257), controlPoint1: NSPoint(x: 735, y: 392), controlPoint2: NSPoint(x: 650, y: 303))
        shield.curve(to: NSPoint(x: 289, y: 530), controlPoint1: NSPoint(x: 374, y: 303), controlPoint2: NSPoint(x: 289, y: 392))
        shield.line(to: NSPoint(x: 289, y: 705))
        shield.curve(to: NSPoint(x: 512, y: 790), controlPoint1: NSPoint(x: 356, y: 720), controlPoint2: NSPoint(x: 434, y: 748))
        shield.close()
        NSColor.white.withAlphaComponent(0.96).setStroke(); shield.lineWidth = 39; shield.lineJoinStyle = .round; shield.stroke()
        let line = NSBezierPath(); line.move(to: NSPoint(x: 512, y: 678)); line.line(to: NSPoint(x: 512, y: 480)); line.lineWidth = 42; line.lineCapStyle = .round; line.stroke()
        NSColor.white.setFill(); NSBezierPath(ovalIn: NSRect(x: 490, y: 384, width: 44, height: 44)).fill()
        image.unlockFocus()
        let bitmap = NSBitmapImageRep(data: image.tiffRepresentation!)!
        let name = "icon_\(size)x\(size)" + (scale == 2 ? "@2x" : "") + ".png"
        try bitmap.representation(using: .png, properties: [:])!.write(to: iconset.appendingPathComponent(name))
    }
}

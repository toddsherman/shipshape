import AppKit

// Shipshape's logo: a ship with hull, mast, mainsail and jib over a line of waves. The app icon (native/make-icon.swift)
// draws it on its tile, and the app draws it beside its name and in the menu bar, so the logo is the same everywhere.
// It's drawn rather than taken from SF Symbols, whose license rules out app icons and logos. Coordinates are in the
// icon's 1024-point canvas, with y up; `box` is the part the ship covers.
enum ShipMark {
    static let box = CGRect(x: 222, y: 186, width: 580, height: 640)
    // The ship as filled outlines, its mast included.
    static let ship: CGPath = {
        let path = CGMutablePath()
        path.move(to: CGPoint(x: 236, y: 400)); path.addLine(to: CGPoint(x: 788, y: 400))
        path.addCurve(to: CGPoint(x: 690, y: 282), control1: CGPoint(x: 760, y: 340), control2: CGPoint(x: 730, y: 296))
        path.addLine(to: CGPoint(x: 334, y: 282))
        path.addCurve(to: CGPoint(x: 236, y: 400), control1: CGPoint(x: 294, y: 296), control2: CGPoint(x: 264, y: 340))
        path.closeSubpath()
        let mast = CGMutablePath(); mast.move(to: CGPoint(x: 512, y: 410)); mast.addLine(to: CGPoint(x: 512, y: 812))
        path.addPath(mast.copy(strokingWithWidth: 26, lineCap: .round, lineJoin: .round, miterLimit: 10))
        path.move(to: CGPoint(x: 488, y: 790))
        path.addCurve(to: CGPoint(x: 282, y: 446), control1: CGPoint(x: 390, y: 695), control2: CGPoint(x: 320, y: 578))
        path.addLine(to: CGPoint(x: 488, y: 446)); path.closeSubpath()
        path.move(to: CGPoint(x: 536, y: 744))
        path.addCurve(to: CGPoint(x: 712, y: 446), control1: CGPoint(x: 620, y: 661), control2: CGPoint(x: 680, y: 559))
        path.addLine(to: CGPoint(x: 536, y: 446)); path.closeSubpath()
        return path
    }()
    // The waves as a filled outline, drawn lighter than the ship.
    static let waves: CGPath = {
        let line = CGMutablePath()
        line.move(to: CGPoint(x: 262, y: 214))
        for crest in 0..<4 {
            let x = 262 + CGFloat(crest) * 125
            line.addCurve(to: CGPoint(x: x + 125, y: 214), control1: CGPoint(x: x + 40, y: 254), control2: CGPoint(x: x + 85, y: 174))
        }
        return line.copy(strokingWithWidth: 28, lineCap: .round, lineJoin: .round, miterLimit: 10)
    }()
    static let wavesOpacity = 0.6
    // Maps `box` into the middle of `rect`, keeping its proportions. A flipped rect has y down, as in SwiftUI.
    static func transform(fitting rect: CGRect, flipped: Bool) -> CGAffineTransform {
        let scale = min(rect.width / box.width, rect.height / box.height)
        return CGAffineTransform(translationX: rect.midX, y: rect.midY).scaledBy(x: scale, y: flipped ? -scale : scale).translatedBy(x: -box.midX, y: -box.midY)
    }
    static func draw(in context: CGContext, fitting rect: CGRect, color: CGColor) {
        var transform = transform(fitting: rect, flipped: false)
        for (path, opacity) in [(ship, 1.0), (waves, wavesOpacity)] {
            guard let placed = path.copy(using: &transform) else { continue }
            context.addPath(placed)
            context.setFillColor(color.copy(alpha: color.alpha * opacity) ?? color)
            context.fillPath()
        }
    }
    // The menu bar's version: a template image, which macOS colors to suit the menu bar.
    static func template(height: CGFloat) -> NSImage {
        let image = NSImage(size: NSSize(width: (height * box.width / box.height).rounded(), height: height), flipped: false) { rect in
            guard let context = NSGraphicsContext.current?.cgContext else { return false }
            draw(in: context, fitting: rect, color: NSColor.black.cgColor)
            return true
        }
        image.isTemplate = true
        return image
    }
}

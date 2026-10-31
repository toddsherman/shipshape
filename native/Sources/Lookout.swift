import SwiftUI

// The lookout in the crow's nest, always at his post beside Check now. While a check runs he watches the horizon through
// his telescope, to the left and then to the right, on a mast that rocks gently; when it ends he settles back and stands
// still, and nothing is redrawn until the next check. He's drawn rather than an image, so he takes the color around him in
// light and dark mode. With Reduce Motion on he doesn't move, and during a check faces the other way every few seconds.
struct Lookout: View {
    var watching: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var started: Date?  // when this watch began; nil once he has settled
    @State private var stopped: Date?  // when the check ended, while he settles
    private static let ease = 0.7      // seconds to get moving, and to settle back
    var body: some View {
        TimelineView(.animation(minimumInterval: reduceMotion ? 0.5 : 1.0 / 30, paused: started == nil)) { timeline in
            LookoutDrawing(time: started.map { timeline.date.timeIntervalSince($0) } ?? 0, energy: energy(at: timeline.date), still: reduceMotion)
        }
        .opacity(watching ? 1 : 0.6).animation(.easeInOut(duration: Self.ease), value: watching)
        .accessibilityElement().accessibilityLabel("Checking").accessibilityHidden(!watching)
        .task(id: watching) {
            if watching { (started, stopped) = (Date(), nil) }
            else if started != nil {
                stopped = Date()
                try? await Task.sleep(nanoseconds: UInt64(Self.ease * 1_000_000_000))
                if !Task.isCancelled { (started, stopped) = (nil, nil) }
            }
        }
    }
    func energy(at date: Date) -> Double {
        guard let started else { return 0 }
        let rising = date.timeIntervalSince(started) / Self.ease, falling = stopped.map { 1 - date.timeIntervalSince($0) / Self.ease } ?? 1
        let level = min(max(min(rising, falling), 0), 1)
        return level * level * (3 - 2 * level)
    }
}

// One frame, drawn on a 100-by-100 grid with the mast at x = 50. The mast and rigging are paler so that he stands in front of them.
struct LookoutDrawing: View {
    let time: Double
    var energy = 1.0   // 1 on watch; 0 standing at rest, facing left, which is also how each watch begins
    var still = false  // Reduce Motion: nothing moves, and he only faces the other way
    private var motion: Double { still ? 0 : energy }
    private static let watch = 6.0  // seconds to look both ways: two seconds each way and a one-second turn after each
    // Which way he faces: -1 is left and 1 is right. Between them he swings the telescope around past you, so it shortens to nothing halfway.
    var facing: Double {
        let t = time.truncatingRemainder(dividingBy: Self.watch)
        if still { return t < 3 ? -1 : 1 }
        func turn(_ x: Double) -> Double { -cos(.pi * x * x * (3 - 2 * x)) }  // from -1 to 1, easing in and out
        let looking: Double
        switch t {
        case ..<2: looking = -1
        case ..<3: looking = turn(t - 2)
        case ..<5: looking = 1
        default: looking = -turn(t - 5)
        }
        return -1 + (looking + 1) * motion
    }
    var body: some View {
        Canvas { context, size in
            let unit = min(size.width, size.height) / 100
            context.translateBy(x: (size.width - 100 * unit) / 2, y: (size.height - 100 * unit) / 2)
            context.scaleBy(x: unit, y: unit)
            // The ship rocks about the foot of the mast.
            context.translateBy(x: 50, y: 110)
            context.rotate(by: .degrees(2.2 * motion * sin(time * 2 * .pi / 5)))
            context.translateBy(x: -50, y: -110)
            rigging(context)
            pennant(context)
            sailor(context)
            nest(context)
        }
    }
    private func rigging(_ context: GraphicsContext) {
        var context = context
        context.opacity = 0.42
        var mast = Path()
        mast.move(to: CGPoint(x: 48.9, y: 2)); mast.addLine(to: CGPoint(x: 51.1, y: 2)); mast.addLine(to: CGPoint(x: 52.6, y: 100)); mast.addLine(to: CGPoint(x: 47.4, y: 100)); mast.closeSubpath()
        context.fill(mast, with: .foreground)
        var ropes = Path()
        for side in [-1.0, 1.0] {
            ropes.move(to: CGPoint(x: 50 + 1.2 * side, y: 7)); ropes.addLine(to: CGPoint(x: 50 + 24 * side, y: 59))
            ropes.move(to: CGPoint(x: 50 + 15 * side, y: 85)); ropes.addLine(to: CGPoint(x: 50 + 2.4 * side, y: 96))
        }
        context.stroke(ropes, with: .foreground, lineWidth: 1.5)
    }
    private func pennant(_ context: GraphicsContext) {
        let flutter = time * 2 * .pi * 1.3
        func wave(_ x: Double) -> Double { (motion * sin(flutter - x / 5) + (1 - motion) * sin(-x / 5)) * x / 18 * 1.5 }
        var flag = Path()
        flag.move(to: CGPoint(x: 51, y: 1))
        for x in stride(from: 3.0, through: 18, by: 3) { flag.addLine(to: CGPoint(x: 51 + x, y: 1 + x / 18 * 4 + wave(x))) }
        for x in stride(from: 15.0, through: 0, by: -3) { flag.addLine(to: CGPoint(x: 51 + x, y: 9 - x / 18 * 4 + wave(x))) }
        flag.closeSubpath()
        context.fill(flag, with: .foreground)
    }
    private func sailor(_ context: GraphicsContext) {
        var context = context
        // He's the point of the picture, so he's drawn large for the nest, growing from the waist.
        context.translateBy(x: 50, y: 62)
        context.scaleBy(x: 1.09, y: 1.09)
        context.translateBy(x: -50, y: -62)
        let side = facing, lean = 1.6 * side
        var body = Path()
        body.addEllipse(in: CGRect(x: 43.7 + lean, y: 24, width: 12.6, height: 13.4))  // head
        body.addRoundedRect(in: CGRect(x: 43.9 + lean, y: 19, width: 12.2, height: 7.5), cornerSize: CGSize(width: 3.2, height: 3.2))  // cap
        body.addRoundedRect(in: CGRect(x: 42.4 + lean, y: 25, width: 15.2, height: 2.2), cornerSize: CGSize(width: 1, height: 1))  // its band
        // Neck and sloping shoulders, narrowing to the waist.
        let shoulder = lean / 2
        body.move(to: CGPoint(x: 46.6 + lean, y: 35))
        body.addLine(to: CGPoint(x: 53.4 + lean, y: 35))
        body.addQuadCurve(to: CGPoint(x: 61 + shoulder, y: 44), control: CGPoint(x: 60 + shoulder, y: 38.5))
        body.addLine(to: CGPoint(x: 58.5, y: 63)); body.addLine(to: CGPoint(x: 41.5, y: 63)); body.addLine(to: CGPoint(x: 39 + shoulder, y: 44))
        body.addQuadCurve(to: CGPoint(x: 46.6 + lean, y: 35), control: CGPoint(x: 40 + shoulder, y: 38.5))
        context.fill(body, with: .foreground)
        // What he points: everything here is drawn facing right, and squeezing it sideways swings it around him.
        var facingSide = context
        facingSide.translateBy(x: 50 + lean, y: 0)
        facingSide.scaleBy(x: side, y: 1)
        var peak = Path()
        peak.move(to: CGPoint(x: 5, y: 24.8)); peak.addLine(to: CGPoint(x: 14, y: 27)); peak.addLine(to: CGPoint(x: 5, y: 28.2)); peak.closeSubpath()
        facingSide.fill(peak, with: .foreground)
        let tilt = -6 + 3 * motion * sin(time * 2 * .pi / 2.3)
        var scope = facingSide
        scope.translateBy(x: 5.5, y: 31)
        scope.rotate(by: .degrees(tilt))
        var tube = Path()
        for (start, length, half) in [(0.0, 8.5, 1.7), (8, 9.5, 2.3), (17, 10, 3), (26.5, 2, 3.7)] {
            tube.addRoundedRect(in: CGRect(x: start, y: -half, width: length, height: half * 2), cornerSize: CGSize(width: 0.8, height: 0.8))
        }
        scope.fill(tube, with: .foreground)
        // The near arm holds up the telescope, and the far hand rests on the rim.
        let angle = tilt * .pi / 180, hold = CGPoint(x: 5.5 + 13 * cos(angle), y: 31 + 13 * sin(angle))
        var arms = Path()
        arms.move(to: CGPoint(x: 8, y: 43.5)); arms.addLine(to: CGPoint(x: 16.5, y: 50.5)); arms.addLine(to: hold)
        arms.move(to: CGPoint(x: -8, y: 43.5)); arms.addLine(to: CGPoint(x: -14.5, y: 51)); arms.addLine(to: CGPoint(x: -14, y: 59))
        facingSide.stroke(arms, with: .foreground, style: StrokeStyle(lineWidth: 4.8, lineCap: .round, lineJoin: .round))
    }
    // The barrel of the nest: a rim and two bands of staves, bowed like a cask, with thin gaps that keep them apart at small sizes.
    private func nest(_ context: GraphicsContext) {
        func half(_ y: Double) -> Double { 23.5 - 0.009 * (y - 65) * (y - 65) }
        func band(_ top: Double, _ bottom: Double) -> Path {
            var path = Path()
            path.move(to: CGPoint(x: 50 - half(top), y: top)); path.addLine(to: CGPoint(x: 50 + half(top), y: top))
            path.addQuadCurve(to: CGPoint(x: 50 + half(bottom), y: bottom), control: CGPoint(x: 50 + half((top + bottom) / 2) + 0.4, y: (top + bottom) / 2))
            path.addLine(to: CGPoint(x: 50 - half(bottom), y: bottom))
            path.addQuadCurve(to: CGPoint(x: 50 - half(top), y: top), control: CGPoint(x: 50 - half((top + bottom) / 2) - 0.4, y: (top + bottom) / 2))
            return path
        }
        var barrel = Path()
        barrel.addRoundedRect(in: CGRect(x: 24, y: 58, width: 52, height: 5), cornerSize: CGSize(width: 2.2, height: 2.2))
        barrel.addPath(band(64.8, 73))
        barrel.addPath(band(74.8, 84))
        context.fill(barrel, with: .foreground)
    }
}

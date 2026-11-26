// Builds the tray icons in assets/brand/tray/ from faro-icon.svg:
//
//   swift assets/brand/make-tray-icons.swift
//
// - faro-menubar.png, faro-menubar@2x.png (18 and 36 px): the macOS menu-bar
//   icon. Black on transparent, for use as a template image: macOS keeps only
//   the alpha and draws it in the menu bar's own colour.
// - faro-tray.ico (16, 20, 24, 32, 40 and 48 px): the Windows notification
//   area icon, in the logo's colours, one size per display scale from 100%
//   to 300%.
//
// Needs macOS 14 or later (NSImage reads SVG from then on).
import AppKit

let brand = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
let out = brand.appendingPathComponent("tray")
guard let logo = NSImage(contentsOf: brand.appendingPathComponent("faro-icon.svg")) else {
    fatalError("cannot read faro-icon.svg (NSImage reads SVG on macOS 14 and later)")
}
try FileManager.default.createDirectory(at: out, withIntermediateDirectories: true)

/// The logo drawn in a `px`-square, aspect kept, centred, `inset` pixels
/// from each edge. `black` fills it with black, keeping only its shape.
func render(_ px: Int, inset: CGFloat, black: Bool) -> Data {
    let rep = NSBitmapImageRep(
        bitmapDataPlanes: nil, pixelsWide: px, pixelsHigh: px, bitsPerSample: 8,
        samplesPerPixel: 4, hasAlpha: true, isPlanar: false, colorSpaceName: .deviceRGB,
        bytesPerRow: 0, bitsPerPixel: 0)!
    rep.size = NSSize(width: px, height: px)
    NSGraphicsContext.saveGraphicsState()
    NSGraphicsContext.current = NSGraphicsContext(bitmapImageRep: rep)
    NSGraphicsContext.current!.imageInterpolation = .high
    let box = CGFloat(px) - 2 * inset
    let scale = min(box / logo.size.width, box / logo.size.height)
    let w = logo.size.width * scale, h = logo.size.height * scale
    let rect = NSRect(x: (CGFloat(px) - w) / 2, y: (CGFloat(px) - h) / 2, width: w, height: h)
    logo.draw(in: rect)
    if black {
        NSColor.black.setFill()
        rect.fill(using: .sourceAtop)
    }
    NSGraphicsContext.restoreGraphicsState()
    return rep.representation(using: .png, properties: [:])!
}

// macOS: 18 pt canvas, the mark 16 pt tall, as Apple's menu-bar icons are.
try render(18, inset: 1, black: true).write(to: out.appendingPathComponent("faro-menubar.png"))
try render(36, inset: 2, black: true).write(to: out.appendingPathComponent("faro-menubar@2x.png"))

// Windows: an .ico of PNG images (Windows Vista and later read these).
let sizes = [16, 20, 24, 32, 40, 48]
let pngs = sizes.map { render($0, inset: 0, black: false) }
var ico = Data()
func le16(_ v: Int) { ico.append(contentsOf: [UInt8(v & 0xff), UInt8(v >> 8 & 0xff)]) }
func le32(_ v: Int) { le16(v & 0xffff); le16(v >> 16) }
le16(0); le16(1); le16(sizes.count)  // reserved, type 1 (icon), image count
var offset = 6 + 16 * sizes.count
for (size, png) in zip(sizes, pngs) {
    ico.append(contentsOf: [UInt8(size), UInt8(size), 0, 0])  // width, height, no palette
    le16(1); le16(32)  // colour planes, bits per pixel
    le32(png.count); le32(offset)
    offset += png.count
}
pngs.forEach { ico.append($0) }
try ico.write(to: out.appendingPathComponent("faro-tray.ico"))
print("wrote \(out.path)")

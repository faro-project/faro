import AVFoundation
import SwiftUI

/// A camera view that reads one QR code and hands back its text. The
/// camera is used only for this (the permission text says so), and never
/// outside this sheet.
@MainActor
struct QRScanner: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: UIViewControllerRepresentableContext<QRScanner>) -> QRCameraController {
        let c = QRCameraController()
        c.onCode = onCode
        return c
    }

    func updateUIViewController(_ controller: QRCameraController, context: UIViewControllerRepresentableContext<QRScanner>) {}
}

final class QRCameraController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private let session = AVCaptureSession()
    private var done = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        AVCaptureDevice.requestAccess(for: .video) { granted in
            DispatchQueue.main.async { granted ? self.configure() : self.showDenied() }
        }
    }

    private func configure() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input)
        else { return showDenied() }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return showDenied() }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let layer = AVCaptureVideoPreviewLayer(session: session)
        layer.videoGravity = .resizeAspectFill
        layer.frame = view.bounds
        view.layer.addSublayer(layer)
        DispatchQueue.global(qos: .userInitiated).async { self.session.startRunning() }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        view.layer.sublayers?.forEach { $0.frame = view.bounds }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    private func showDenied() {
        let label = UILabel()
        label.text = "Faro can't use the camera. Paste the link instead, or allow the camera in Settings."
        label.textColor = .white
        label.numberOfLines = 0
        label.textAlignment = .center
        label.frame = view.bounds.insetBy(dx: 24, dy: 24)
        label.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.addSubview(label)
    }

    func metadataOutput(
        _ output: AVCaptureMetadataOutput, didOutput objects: [AVMetadataObject],
        from connection: AVCaptureConnection
    ) {
        guard !done,
              let text = (objects.first as? AVMetadataMachineReadableCodeObject)?.stringValue
        else { return }
        done = true
        session.stopRunning()
        onCode?(text)
    }
}

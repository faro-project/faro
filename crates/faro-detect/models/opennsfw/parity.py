"""Check the converted OpenNSFW models against the original Caffe model.

    python3 -I parity.py --prototxt deploy.prototxt \
        --caffemodel resnet_50_1by2_nsfw.caffemodel --models DIR

The reference is OpenCV's Caffe importer (`cv2.dnn.readNetFromCaffe`),
which runs Yahoo's files directly and shares no code with convert.py. Every
model gets the same input tensors, drawn here and never explicit: solid
colours, gradients and UI-like windows with text. It prints p(nsfw) for
each and exits 1 if a model is further from the reference than its
tolerance (FP32_TOLERANCE, INT8_TOLERANCE, absolute, on p(nsfw)).
`build.sh --parity` installs requirements-parity.txt and runs it.
"""

import argparse
import sys
from pathlib import Path

import cv2
import numpy as np
import onnxruntime as ort

sys.path.insert(0, str(Path(__file__).resolve().parent))
from convert import SIDE, caffe_tensor  # noqa: E402

FP32_TOLERANCE = 1e-4
INT8_TOLERANCE = 0.05


def window(bg, ink, accent, title, lines, seed):
    """A UI-like window, RGB: title bar, sidebar, text and a panel."""
    rng = np.random.default_rng(seed)
    img = np.empty((SIDE * 3, SIDE * 4, 3), np.uint8)
    img[:] = bg
    h, w = img.shape[:2]
    bar = tuple(int(max(0, c - 30)) for c in bg)
    cv2.rectangle(img, (0, 0), (w, 36), bar, -1)
    for i, c in enumerate([(255, 95, 86), (255, 189, 46), (39, 201, 63)]):
        cv2.circle(img, (20 + 22 * i, 18), 7, c, -1)
    cv2.putText(img, title, (100, 25), cv2.FONT_HERSHEY_SIMPLEX, 0.6, ink, 1, cv2.LINE_AA)
    side = tuple(int(max(0, c - 15)) for c in bg)
    cv2.rectangle(img, (0, 36), (150, h), side, -1)
    for i in range(8):
        cv2.putText(img, f"Item {i + 1}", (16, 70 + 28 * i), cv2.FONT_HERSHEY_SIMPLEX, 0.5, ink, 1, cv2.LINE_AA)
    y = 70
    for text in lines:
        cv2.putText(img, text, (170, y), cv2.FONT_HERSHEY_SIMPLEX, 0.55, ink, 1, cv2.LINE_AA)
        y += 26
    x0 = int(rng.integers(400, 560))
    cv2.rectangle(img, (x0, 380), (x0 + 260, 620), accent, -1)
    cv2.rectangle(img, (170, 640), (330, 670), accent, -1)
    cv2.putText(img, "OK", (235, 662), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (255, 255, 255), 1, cv2.LINE_AA)
    return img


def test_images():
    text = [
        "Quarterly planning notes",
        "- Ship the installer for Intel and Apple Silicon",
        "- Review the release checklist with the team",
        "- Update the dependency licences",
        "def main(): return run(sys.argv[1:])",
        "Total: 1,234.56   Due: 2026-12-01",
        "The quick brown fox jumps over the lazy dog.",
    ]
    images = {}
    for name, c in [
        ("black", (0, 0, 0)),
        ("white", (255, 255, 255)),
        ("grey", (128, 128, 128)),
        ("red", (220, 30, 30)),
        ("green", (30, 200, 60)),
        ("blue", (40, 60, 210)),
        ("beige", (225, 190, 160)),
        ("yellow", (240, 220, 40)),
    ]:
        img = np.empty((SIDE, SIDE, 3), np.uint8)
        img[:] = c
        images[f"solid-{name}"] = img
    t = np.linspace(0, 255, SIDE).astype(np.uint8)
    images["gradient-h"] = np.stack([np.tile(t, (SIDE, 1))] * 3, axis=-1)
    images["gradient-rgb"] = np.stack(
        [np.tile(t, (SIDE, 1)), np.tile(t[:, None], (1, SIDE)), np.full((SIDE, SIDE), 128, np.uint8)], axis=-1
    )
    images["ui-light"] = window((246, 246, 246), (30, 30, 30), (0, 122, 255), "Notes", text, 1)
    images["ui-dark"] = window((30, 30, 32), (220, 220, 220), (94, 92, 230), "Terminal", text, 2)
    images["ui-sepia"] = window((244, 236, 216), (80, 60, 40), (200, 120, 60), "Reader", text, 3)
    sheet = np.full((SIDE * 3, SIDE * 4, 3), 255, np.uint8)
    for x in range(0, sheet.shape[1], 90):
        cv2.line(sheet, (x, 0), (x, sheet.shape[0]), (200, 200, 200), 1)
    for y in range(0, sheet.shape[0], 24):
        cv2.line(sheet, (0, y), (sheet.shape[1], y), (200, 200, 200), 1)
        cv2.putText(sheet, f"{y * 37 % 1000:>6}", (8, y + 18), cv2.FONT_HERSHEY_SIMPLEX, 0.45, (0, 0, 0), 1)
    images["ui-spreadsheet"] = sheet
    return images


def to_224(rgb):
    if rgb.shape[:2] == (SIDE, SIDE):
        return rgb
    return cv2.resize(rgb, (SIDE, SIDE), interpolation=cv2.INTER_AREA)


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--prototxt", required=True, type=Path)
    ap.add_argument("--caffemodel", required=True, type=Path)
    ap.add_argument("--models", required=True, type=Path, help="directory with opennsfw-{fp32,int8}.onnx")
    a = ap.parse_args(argv)

    ref = cv2.dnn.readNetFromCaffe(str(a.prototxt), str(a.caffemodel))
    so = ort.SessionOptions()
    so.intra_op_num_threads = 1
    sessions = {
        k: ort.InferenceSession(str(a.models / f"opennsfw-{k}.onnx"), so, providers=["CPUExecutionProvider"])
        for k in ("fp32", "int8")
    }
    tolerance = {"fp32": FP32_TOLERANCE, "int8": INT8_TOLERANCE}
    worst = {k: 0.0 for k in sessions}
    print(f"{'image':<16} {'caffe':>9} {'fp32':>9} {'int8':>9}   p(nsfw)")
    for name, rgb in test_images().items():
        x = caffe_tensor(to_224(rgb))
        ref.setInput(x)
        expected = float(ref.forward("prob").reshape(-1)[1])
        row = [f"{name:<16} {expected:9.6f}"]
        for k, s in sessions.items():
            got = float(s.run(["prob"], {"data": x})[0].reshape(-1)[1])
            worst[k] = max(worst[k], abs(got - expected))
            row.append(f"{got:9.6f}")
        print(" ".join(row))
    ok = True
    for k, d in worst.items():
        verdict = "ok" if d <= tolerance[k] else "FAIL"
        ok &= d <= tolerance[k]
        print(f"{k}: max |difference| {d:.2e} (tolerance {tolerance[k]:g}) {verdict}")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

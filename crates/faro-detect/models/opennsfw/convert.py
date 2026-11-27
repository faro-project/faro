"""Convert Yahoo's OpenNSFW Caffe model to ONNX, and quantize it to int8.

    python3 -I convert.py --prototxt deploy.prototxt \
        --caffemodel resnet_50_1by2_nsfw.caffemodel --out DIR

writes DIR/opennsfw-fp32.onnx and DIR/opennsfw-int8.onnx. `build.sh` runs
it with the tool versions pinned in requirements.txt; run that rather than
this file directly (docs/DEVELOPMENT.md "The image model").

What the conversion does, and nothing else:

* The network is read from Yahoo's `deploy.prototxt` and the weights from
  Yahoo's `.caffemodel`, both decoded here (no Caffe install, no third-party
  port). Every layer maps to a standard ONNX op.
* Each BatchNorm + Scale pair is folded into the convolution before it,
  in float64, then rounded to float32. Caffe's max pooling rounds its
  output size up, so pooling uses `ceil_mode`.
* The int8 model is the fp32 one quantized by ONNX Runtime: QDQ format,
  int8 weights per output channel, uint8 activations per tensor, with
  min/max ranges calibrated on synthetic, non-explicit images that this
  script draws (solid colours, gradients and UI-like windows). The stem
  and the head stay in float (`is_float_node`).

Inputs and outputs: `data`, float32 [1, 3, 224, 224], BGR, 0..255 minus
the Caffe mean (104, 117, 123); `prob`, float32 [1, 2], softmax over
(sfw, nsfw). The same bytes come out every time on the same kind of
machine, so build.sh can check them against the manifests' BLAKE3.
"""

import argparse
import re
import sys
import warnings
from pathlib import Path

import numpy as np
import onnx
from onnx import TensorProto, helper, numpy_helper

OPSET = 13
IR_VERSION = 7
INPUT = "data"
OUTPUT = "prob"
SIDE = 224
CAFFE_MEAN_BGR = (104.0, 117.0, 123.0)
BN_EPS_DEFAULT = 1e-5
CALIBRATION_IMAGES = 96
CALIBRATION_SEED = 20161


# ---- protobuf wire format (just enough for a .caffemodel) ----------------


def _varint(buf, pos):
    shift = result = 0
    while True:
        b = buf[pos]
        pos += 1
        result |= (b & 0x7F) << shift
        if not b & 0x80:
            return result, pos
        shift += 7
        if shift > 63:
            raise ValueError("varint too long")


def _fields(buf):
    """Yield (field number, wire type, value) for each field of a message.
    Length-delimited values are memoryviews into `buf`."""
    pos, end = 0, len(buf)
    while pos < end:
        key, pos = _varint(buf, pos)
        field, wire = key >> 3, key & 7
        if wire == 0:
            value, pos = _varint(buf, pos)
        elif wire == 1:
            value, pos = buf[pos : pos + 8], pos + 8
        elif wire == 2:
            n, pos = _varint(buf, pos)
            value, pos = buf[pos : pos + n], pos + n
        elif wire == 5:
            value, pos = buf[pos : pos + 4], pos + 4
        else:
            raise ValueError(f"unsupported wire type {wire}")
        if pos > end:
            raise ValueError("truncated message")
        yield field, wire, value


def _packed_varints(buf):
    out, pos = [], 0
    while pos < len(buf):
        v, pos = _varint(buf, pos)
        out.append(v)
    return out


def _blob(buf):
    """caffe.BlobProto -> float32 array of its shape."""
    dims, legacy, chunks = None, {}, []
    for field, wire, value in _fields(buf):
        if field == 7:  # shape: BlobShape { repeated int64 dim = 1 }
            dims = []
            for f, w, v in _fields(value):
                if f == 1:
                    dims.extend(_packed_varints(v) if w == 2 else [v])
        elif field in (1, 2, 3, 4) and wire == 0:  # num, channels, height, width
            legacy[field] = value
        elif field == 5:  # data
            chunks.append(np.frombuffer(value, dtype="<f4"))
        elif field == 8:
            raise ValueError("double_data blobs are not supported")
    if dims is None:
        dims = [legacy.get(i, 1) for i in (1, 2, 3, 4)]
    data = np.concatenate(chunks) if chunks else np.zeros(0, "<f4")
    if data.size != int(np.prod(dims)):
        raise ValueError(f"blob has {data.size} values for shape {dims}")
    return data.astype(np.float32).reshape(dims)


def read_caffemodel(path):
    """Layer name -> list of blobs, from a caffe.NetParameter (`layer`, the
    current format)."""
    buf = memoryview(Path(path).read_bytes())
    out = {}
    for field, _, value in _fields(buf):
        if field == 2:
            raise ValueError("V1 `layers` caffemodels are not supported")
        if field != 100:
            continue
        name, blobs = None, []
        for f, _, v in _fields(value):
            if f == 1:
                name = bytes(v).decode()
            elif f == 7:
                blobs.append(_blob(v))
        if blobs:
            if name in out:
                raise ValueError(f"duplicate layer {name!r}")
            out[name] = blobs
    return out


# ---- prototxt (protobuf text format, just enough for deploy.prototxt) ----

_TOKEN = re.compile(r'\s*(?:#[^\n]*\n\s*)*("(?:[^"\\]|\\.)*"|[{}:]|[^\s{}:"#]+)')


def _tokens(text):
    pos = 0
    while True:
        m = _TOKEN.match(text, pos)
        if not m:
            if text[pos:].strip():
                raise ValueError(f"cannot parse prototxt near {text[pos:pos + 40]!r}")
            return
        pos = m.end()
        yield m.group(1)


def _scalar(tok):
    if tok.startswith('"'):
        return tok[1:-1]
    try:
        return int(tok)
    except ValueError:
        pass
    try:
        return float(tok)
    except ValueError:
        return tok  # an enum value or true/false


class Msg:
    """A parsed text-format message: key -> list of values."""

    def __init__(self):
        self.items = {}

    def all(self, key):
        return self.items.get(key, [])

    def get(self, key, default=None):
        v = self.all(key)
        if len(v) > 1:
            raise ValueError(f"{key} is repeated")
        return v[0] if v else default

    def keys(self):
        return set(self.items)


def _parse(tokens, nested):
    msg = Msg()
    for tok in tokens:
        if tok == "}":
            if not nested:
                raise ValueError("unbalanced }")
            return msg
        key = tok
        nxt = next(tokens)
        if nxt == ":":
            nxt = next(tokens)
        if nxt == "{":
            value = _parse(tokens, True)
        else:
            value = _scalar(nxt)
        msg.items.setdefault(key, []).append(value)
    if nested:
        raise ValueError("missing }")
    return msg


def read_prototxt(path):
    return _parse(_tokens(Path(path).read_text()), False)


# ---- graph ---------------------------------------------------------------


def _only(msg, allowed, what):
    extra = msg.keys() - set(allowed)
    if extra:
        raise ValueError(f"{what}: unsupported fields {sorted(extra)}")


def build_fp32(net, blobs):
    layers = net.all("layer")
    nodes, inits, used = [], [], set()
    cur = {}  # Caffe blob name -> current ONNX tensor name

    def init(name, array):
        inits.append(numpy_helper.from_array(np.ascontiguousarray(array, np.float32), name))

    def emit(op, inputs, output, name, **attrs):
        nodes.append(helper.make_node(op, inputs, [output], name=name, **attrs))

    i = 0
    while i < len(layers):
        layer = layers[i]
        name, kind = layer.get("name"), layer.get("type")
        bottoms, tops = layer.all("bottom"), layer.all("top")
        i += 1
        if kind == "Input":
            dims = layer.get("input_param").get("shape").all("dim")
            if dims != [1, 3, SIDE, SIDE]:
                raise ValueError(f"unexpected input shape {dims}")
            cur[tops[0]] = INPUT
            continue
        x = [cur[b] for b in bottoms]
        if kind == "Convolution":
            p = layer.get("convolution_param")
            _only(p, {"num_output", "pad", "kernel_size", "stride", "bias_term",
                      "weight_filler", "bias_filler"}, name)
            w, *rest = blobs[name]
            used.add(name)
            n_out, k = p.get("num_output"), p.get("kernel_size")
            if w.shape[0] != n_out or w.shape[2:] != (k, k):
                raise ValueError(f"{name}: weights {w.shape}")
            has_bias = p.get("bias_term", "true") != "false"
            b = rest[0].reshape(-1) if has_bias else np.zeros(n_out, np.float32)
            # Fold the BatchNorm + Scale pair that follows, in place.
            bn, sc = layers[i], layers[i + 1]
            if not (bn.get("type") == "BatchNorm" and sc.get("type") == "Scale"
                    and bn.all("bottom") == bn.all("top") == tops
                    and sc.all("bottom") == sc.all("top") == tops):
                raise ValueError(f"{name} is not followed by BatchNorm and Scale")
            i += 2
            bnp = bn.get("batch_norm_param")
            _only(bnp, {"use_global_stats", "eps"}, bn.get("name"))
            if bnp.get("use_global_stats") != "true":
                raise ValueError(f"{bn.get('name')}: needs use_global_stats")
            eps = float(bnp.get("eps", BN_EPS_DEFAULT))
            mean, var, factor = blobs[bn.get("name")]
            used.add(bn.get("name"))
            f = float(factor.reshape(-1)[0])
            f = 0.0 if f == 0 else 1.0 / f
            mean = mean.reshape(-1).astype(np.float64) * f
            var = var.reshape(-1).astype(np.float64) * f
            if sc.get("scale_param").get("bias_term") != "true":
                raise ValueError(f"{sc.get('name')}: needs bias_term")
            gamma, beta = (v.reshape(-1).astype(np.float64) for v in blobs[sc.get("name")])
            used.add(sc.get("name"))
            s = gamma / np.sqrt(var + eps)
            wf = w.astype(np.float64) * s[:, None, None, None]
            bf = (b.astype(np.float64) - mean) * s + beta
            out = tops[0]
            init(f"{name}.weight", wf.astype(np.float32))
            init(f"{name}.bias", bf.astype(np.float32))
            pad, stride = p.get("pad", 0), p.get("stride", 1)
            emit("Conv", [x[0], f"{name}.weight", f"{name}.bias"], name, name,
                 kernel_shape=[k, k], pads=[pad] * 4, strides=[stride, stride])
            cur[out] = name
        elif kind == "ReLU":
            if layer.get("relu_param") is not None:
                raise ValueError(f"{name}: leaky ReLU is not supported")
            emit("Relu", x, name, name)
            cur[tops[0]] = name
        elif kind == "Eltwise":
            if layer.get("eltwise_param") is not None:
                raise ValueError(f"{name}: only a plain SUM is supported")
            emit("Add", x, name, name)
            cur[tops[0]] = name
        elif kind == "Pooling":
            p = layer.get("pooling_param")
            _only(p, {"pool", "kernel_size", "stride"}, name)
            k, s = p.get("kernel_size"), p.get("stride", 1)
            op = {"MAX": "MaxPool", "AVE": "AveragePool"}[p.get("pool")]
            # Caffe rounds pooled sizes up; with no padding that is ceil_mode.
            emit(op, x, name, name, kernel_shape=[k, k], strides=[s, s], ceil_mode=1)
            cur[tops[0]] = name
        elif kind == "InnerProduct":
            w, b = blobs[name]
            used.add(name)
            n_out = layer.get("inner_product_param").get("num_output")
            if w.shape[0] != n_out:
                raise ValueError(f"{name}: weights {w.shape}")
            init(f"{name}.weight", w.reshape(n_out, -1))
            init(f"{name}.bias", b.reshape(-1))
            emit("Flatten", x, f"{name}.flat", f"{name}.flatten", axis=1)
            emit("Gemm", [f"{name}.flat", f"{name}.weight", f"{name}.bias"], name, name, transB=1)
            cur[tops[0]] = name
        elif kind == "Softmax":
            emit("Softmax", x, OUTPUT, name, axis=1)
            cur[tops[0]] = OUTPUT
        else:
            raise ValueError(f"{name}: unsupported layer type {kind}")
    if cur.get("prob") != OUTPUT:
        raise ValueError("the network does not end in the `prob` softmax")
    unused = set(blobs) - used
    if unused:
        raise ValueError(f"weights for unknown layers: {sorted(unused)}")

    graph = helper.make_graph(
        nodes,
        "opennsfw",
        [helper.make_tensor_value_info(INPUT, TensorProto.FLOAT, [1, 3, SIDE, SIDE])],
        [helper.make_tensor_value_info(OUTPUT, TensorProto.FLOAT, [1, 2])],
        inits,
    )
    model = helper.make_model(
        graph,
        opset_imports=[helper.make_opsetid("", OPSET)],
        producer_name="faro opennsfw convert.py",
        producer_version="1",
        doc_string="OpenNSFW (Yahoo Inc., BSD-2-Clause), converted from the original Caffe model.",
    )
    model.ir_version = IR_VERSION
    onnx.checker.check_model(model, full_check=True)
    return model


# ---- calibration images (synthetic, non-explicit) ------------------------


def synthetic_images(n, seed):
    """Deterministic HxWx3 uint8 RGB images: solid colours, gradients and
    UI-like windows with lines of fake text."""
    rng = np.random.default_rng(seed)
    out = []
    for i in range(n):
        kind = i % 3
        if kind == 0:
            img = np.empty((SIDE, SIDE, 3), np.uint8)
            img[:] = rng.integers(0, 256, 3, dtype=np.uint8)
        elif kind == 1:
            a, b = rng.integers(0, 256, (2, 3)).astype(np.float64)
            t = np.linspace(0.0, 1.0, SIDE)[:, None, None]
            row = a + (b - a) * t
            img = np.broadcast_to(row, (SIDE, SIDE, 3)).astype(np.uint8)
            if rng.integers(2):
                img = img.transpose(1, 0, 2)
        else:
            bg = rng.integers(0, 256, 3)
            img = np.empty((SIDE, SIDE, 3), np.uint8)
            img[:] = bg
            img[:16] = np.clip(bg.astype(int) - 40, 0, 255)  # toolbar
            img[16:, :40] = np.clip(bg.astype(int) - 20, 0, 255)  # sidebar
            ink = 0 if bg.mean() > 128 else 230
            for line in range(rng.integers(5, 15)):
                y = 24 + line * 12
                if y + 4 >= SIDE:
                    break
                x0 = 48
                x1 = int(x0 + rng.integers(40, SIDE - x0))
                img[y : y + 4, x0:x1] = ink
            x, y = (int(v) for v in rng.integers(48, SIDE - 60, 2))
            img[y : y + 50, x : x + 50] = rng.integers(0, 256, 3)  # an image or button
        out.append(np.ascontiguousarray(img))
    return out


def caffe_tensor(rgb):
    """HxWx3 RGB uint8 (already 224x224) -> 1x3x224x224 float32 Caffe input."""
    bgr = rgb[:, :, ::-1].astype(np.float32) - np.array(CAFFE_MEAN_BGR, np.float32)
    return np.ascontiguousarray(bgr.transpose(2, 0, 1)[None])


def is_float_node(name):
    """Nodes the int8 model keeps in float: the stem (conv_1, pool1 and
    stages 0 and 1), whose quantization error the later layers amplify
    most, and the head (fc_nsfw and the softmax), so p(nsfw) isn't rounded
    to 1/255. Quantizing everything puts the int8 model up to 0.25 from
    the original on synthetic images; this keeps it within about 0.06, at
    the same speed. Stages 2 and 3 hold most of the weights."""
    return (
        name in ("conv_1", "relu_1", "pool1", "fc_nsfw", "fc_nsfw.flatten", "prob")
        or "_stage0_" in name
        or "_stage1_" in name
    )


def check_int8(model):
    """No quantized bias may sit at the int32 limit (an overflow)."""
    for t in model.graph.initializer:
        if t.data_type == TensorProto.INT32:
            a = numpy_helper.to_array(t).astype(np.int64)
            if (np.abs(a) >= 2**31 - 1).any():
                raise ValueError(f"{t.name}: quantized value at the int32 limit")


def quantize(fp32_model, fp32_path, int8_path):
    from onnxruntime.quantization import (
        CalibrationDataReader,
        CalibrationMethod,
        QuantFormat,
        QuantType,
        quantize_static,
    )

    class Reader(CalibrationDataReader):
        def __init__(self):
            self.it = iter(synthetic_images(CALIBRATION_IMAGES, CALIBRATION_SEED))

        def get_next(self):
            img = next(self.it, None)
            return None if img is None else {INPUT: caffe_tensor(img)}

    float_nodes = [n.name for n in fp32_model.graph.node if is_float_node(n.name)]
    with warnings.catch_warnings():
        # A float that doesn't fit its cast (an int32 bias overflow, from a
        # channel whose weights are all ~0) is an error, not a warning.
        warnings.simplefilter("error", RuntimeWarning)
        quantize_static(
            str(fp32_path),
            str(int8_path),
            Reader(),
            quant_format=QuantFormat.QDQ,
            per_channel=True,
            activation_type=QuantType.QUInt8,
            weight_type=QuantType.QInt8,
            calibrate_method=CalibrationMethod.MinMax,
            nodes_to_exclude=float_nodes,
        )
    check_int8(onnx.load(str(int8_path)))


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--prototxt", required=True, type=Path)
    ap.add_argument("--caffemodel", required=True, type=Path)
    ap.add_argument("--out", required=True, type=Path)
    a = ap.parse_args(argv)
    a.out.mkdir(parents=True, exist_ok=True)
    model = build_fp32(read_prototxt(a.prototxt), read_caffemodel(a.caffemodel))
    fp32 = a.out / "opennsfw-fp32.onnx"
    fp32.write_bytes(model.SerializeToString(deterministic=True))
    int8 = a.out / "opennsfw-int8.onnx"
    quantize(model, fp32, int8)
    for p in (fp32, int8):
        print(f"{p}: {p.stat().st_size} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

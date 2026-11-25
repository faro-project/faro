//! Tiny hand-encoded ONNX graphs for tests (test builds only).
//!
//! A minimal protobuf writer, enough to encode a weightless ONNX graph, so
//! the runtime path and the benchmark harness are tested end to end without
//! shipping or downloading any model file. The graphs carry no weights at
//! all: they are a few hundred bytes of graph structure.

fn varint(mut v: u64, out: &mut Vec<u8>) {
    while v >= 0x80 {
        out.push((v as u8) | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

fn int(field: u64, v: u64, out: &mut Vec<u8>) {
    varint(field << 3, out);
    varint(v, out);
}

fn bytes(field: u64, b: &[u8], out: &mut Vec<u8>) {
    varint((field << 3) | 2, out);
    varint(b.len() as u64, out);
    out.extend_from_slice(b);
}

fn tensor_value_info(name: &str, dims: &[u64]) -> Vec<u8> {
    let mut shape = Vec::new();
    for &d in dims {
        let mut dim = Vec::new();
        int(1, d, &mut dim); // Dimension.dim_value
        bytes(1, &dim, &mut shape); // TensorShapeProto.dim
    }
    let mut tensor = Vec::new();
    int(1, 1, &mut tensor); // elem_type = FLOAT
    bytes(2, &shape, &mut tensor);
    let mut ty = Vec::new();
    bytes(1, &tensor, &mut ty); // TypeProto.tensor_type
    let mut vi = Vec::new();
    bytes(1, name.as_bytes(), &mut vi);
    bytes(2, &ty, &mut vi);
    vi
}

/// `y = GlobalAveragePool(x)`: x `[1,3,side,side]` → y `[1,3,1,1]`, i.e.
/// the mean of each normalised input channel. With a softmax manifest this
/// is a three-label "classifier" that answers by the dominant colour.
pub(crate) fn mean_pool_model(side: u64) -> Vec<u8> {
    let mut node = Vec::new();
    bytes(1, b"x", &mut node);
    bytes(2, b"y", &mut node);
    bytes(4, b"GlobalAveragePool", &mut node);
    let mut graph = Vec::new();
    bytes(1, &node, &mut graph);
    bytes(2, b"mean_pool", &mut graph);
    bytes(11, &tensor_value_info("x", &[1, 3, side, side]), &mut graph);
    bytes(12, &tensor_value_info("y", &[1, 3, 1, 1]), &mut graph);
    let mut opset = Vec::new();
    bytes(1, b"", &mut opset);
    int(2, 13, &mut opset);
    let mut model = Vec::new();
    int(1, 8, &mut model); // ir_version
    bytes(8, &opset, &mut model);
    bytes(7, &graph, &mut model);
    model
}

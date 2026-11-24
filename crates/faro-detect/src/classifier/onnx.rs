//! ONNX Runtime classifier (feature `onnx`), via the `ort` crate.
//!
//! The session is built from the [`VerifiedModel`]'s in-memory bytes, so
//! what runs is exactly what was hashed. Inference uses one intra-op thread:
//! the service samples about once a minute and must stay under 1% average
//! CPU (§3.4), so latency matters less than not stealing cores.
//!
//! The input tensor is passed to the runtime as a *borrowed* view of the
//! zeroize-on-drop buffer from [`preprocess`]. Known limitation: activations
//! inside ONNX Runtime's own arena are not zeroized by Faro; they are derived
//! features of a classifier-sized (e.g. 224×224) downscale, live only in
//! process memory, and are never persisted.

use super::{
    postprocess, preprocess, Classifier, ImageScores, ModelInfo, TensorLayout, VerifiedModel,
};
use crate::error::DetectError;
use faro_platform::Frame;
use ort::session::builder::GraphOptimizationLevel;
use ort::session::Session;
use ort::value::TensorRef;

fn ort_err(e: impl std::fmt::Display) -> DetectError {
    DetectError::Classifier(format!("onnxruntime: {e}"))
}

/// An ONNX image classifier.
pub struct OnnxClassifier {
    info: ModelInfo,
    session: Session,
    input_name: String,
}

impl std::fmt::Debug for OnnxClassifier {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OnnxClassifier")
            .field("info", &self.info)
            .field("input_name", &self.input_name)
            .finish_non_exhaustive()
    }
}

impl OnnxClassifier {
    /// Build a session from a verified model.
    pub fn new(model: VerifiedModel) -> Result<Self, DetectError> {
        let session = Session::builder()
            .map_err(ort_err)?
            .with_optimization_level(GraphOptimizationLevel::Level3)
            .map_err(ort_err)?
            .with_intra_threads(1)
            .map_err(ort_err)?
            .commit_from_memory(model.bytes())
            .map_err(ort_err)?;
        let input_name = session
            .inputs
            .first()
            .map(|i| i.name.clone())
            .ok_or_else(|| DetectError::Manifest("model has no inputs".into()))?;
        if session.outputs.is_empty() {
            return Err(DetectError::Manifest("model has no outputs".into()));
        }
        Ok(OnnxClassifier {
            info: model.info().clone(),
            session,
            input_name,
        })
    }
}

impl Classifier for OnnxClassifier {
    fn info(&self) -> &ModelInfo {
        &self.info
    }

    fn classify(&mut self, frame: &Frame) -> Result<ImageScores, DetectError> {
        let input = preprocess(frame, &self.info);
        let (w, h) = (
            self.info.input_size.width as usize,
            self.info.input_size.height as usize,
        );
        let shape = match self.info.layout {
            TensorLayout::Nchw => [1usize, 3, h, w],
            TensorLayout::Nhwc => [1usize, h, w, 3],
        };
        let tensor = TensorRef::from_array_view((shape, &input[..])).map_err(ort_err)?;
        let outputs = self
            .session
            .run(ort::inputs![self.input_name.as_str() => tensor])
            .map_err(ort_err)?;
        let (_, data) = outputs[0].try_extract_tensor::<f32>().map_err(ort_err)?;
        postprocess(data, &self.info)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classifier::{ChannelOrder, InputSize, OutputActivation};
    use faro_platform::PixelFormat;

    // Minimal protobuf writer, enough to hand-encode a weightless ONNX graph
    // so the runtime path is tested without shipping any model file.
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

    /// `y = GlobalAveragePool(x)`: x `[1,3,8,8]` → y `[1,3,1,1]`, i.e. the
    /// mean of each normalised input channel.
    fn mean_pool_model() -> Vec<u8> {
        let mut node = Vec::new();
        bytes(1, b"x", &mut node);
        bytes(2, b"y", &mut node);
        bytes(4, b"GlobalAveragePool", &mut node);
        let mut graph = Vec::new();
        bytes(1, &node, &mut graph);
        bytes(2, b"mean_pool", &mut graph);
        bytes(11, &tensor_value_info("x", &[1, 3, 8, 8]), &mut graph);
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

    fn info(bytes: &[u8], order: ChannelOrder) -> ModelInfo {
        ModelInfo {
            name: "mean-pool".into(),
            version: "1".into(),
            file: "m.onnx".into(),
            input_size: InputSize {
                width: 8,
                height: 8,
            },
            labels: vec!["a".into(), "b".into(), "c".into()],
            mean: [0.0; 3],
            std: [0.1; 3],
            channel_order: order,
            layout: TensorLayout::Nchw,
            input_scale: 1.0 / 255.0,
            output: OutputActivation::Softmax,
            license: "Apache-2.0".into(),
            blake3: blake3::hash(bytes).to_hex().to_string(),
        }
    }

    #[test]
    fn runs_a_real_onnx_graph_end_to_end() {
        let model = mean_pool_model();
        let verified =
            VerifiedModel::verify(info(&model, ChannelOrder::Rgb), model.clone()).unwrap();
        let mut c = OnnxClassifier::new(verified).unwrap();
        // Pure red, BGRA-encoded: channel "a" (R) must dominate.
        let f = Frame::new(
            32,
            32,
            PixelFormat::Bgra8,
            0,
            [0, 0, 255, 255].repeat(32 * 32),
        )
        .unwrap();
        let s = c.classify(&f).unwrap();
        assert!(s.get("a").unwrap() > 0.99, "{s:?}");

        // Same frame, BGR model: "c" is now red.
        let verified = VerifiedModel::verify(info(&model, ChannelOrder::Bgr), model).unwrap();
        let mut c = OnnxClassifier::new(verified).unwrap();
        let s = c.classify(&f).unwrap();
        assert!(s.get("c").unwrap() > 0.99, "{s:?}");
    }

    #[test]
    fn garbage_model_is_an_error_not_a_panic() {
        let junk = b"definitely not onnx".to_vec();
        let verified = VerifiedModel::verify(info(&junk, ChannelOrder::Rgb), junk).unwrap();
        assert!(matches!(
            OnnxClassifier::new(verified),
            Err(DetectError::Classifier(_))
        ));
    }

    #[test]
    fn label_count_mismatch_is_an_error() {
        let model = mean_pool_model();
        let mut i = info(&model, ChannelOrder::Rgb);
        i.labels.push("d".into());
        let mut c = OnnxClassifier::new(VerifiedModel::verify(i, model).unwrap()).unwrap();
        let f = Frame::new(4, 4, PixelFormat::Rgba8, 0, vec![0; 64]).unwrap();
        assert!(matches!(c.classify(&f), Err(DetectError::Classifier(_))));
    }
}

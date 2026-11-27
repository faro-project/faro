# Candidate image models: licences and fit

**Audience:** the maintainer, who makes the licence decision for Faro's on-device image classifier (ARCHITECTURE.md §3.5, §11).
**Status:** research memo for issue #23, with the maintainer's decisions of 2026-11-25 (section 1). Nothing here changes code or adds a model.
**Sources checked:** 2026-11-25, every source cited below unless a row says otherwise. Licence files were read from the repository or model hub at that date. Licences on weights change (two of the candidates below changed theirs), so check again before shipping.

No model weights or images were downloaded for this memo. Sizes come from repository and hub file listings. Parameter counts come from the projects' own tables. Anything marked *est.* is my estimate, not a measurement.

---

## 1. Decisions (2026-11-25)

The maintainer answered the open questions in section 3 on 2026-11-25:

1. **Beta baseline: OpenNSFW** (BSD-2-Clause), converted to ONNX and quantized to int8.
2. **Training-data rule (hard rule): no model trained on a dataset with documented child sexual abuse material.** Today that means NudeNet's dataset and LAION-5B. Any dataset with a later finding is added to the list. A model's training data must be disclosed well enough to check this.
3. **ImageNet:** ImageNet-pretrained weights are allowed **for the beta baseline only** (OpenNSFW), relying on the weights' own licence. **Long-term models must not be ImageNet-based.**
4. **Labelled data for Faro's own heads, and how it is screened:** deferred until after the beta.
5. **Deployed-use language in the CLIP model cards, and attribution notices in the model bundle:** follow-ups for the task that ships the model, not decided here.
6. **Faro's own licence:** draft PR #22 rewrites ARCHITECTURE.md §11 for the AGPL, with third-party components permissive only. This memo doesn't touch §11.

What the decisions rule out:

- **GantMan and Falconsai** drop out as beta candidates. Both are ImageNet-based, and the ImageNet allowance covers OpenNSFW only.
- **LAION-trained CLIPs** are refused under rule 2: OpenCLIP `laion2b_*` and `laion400m_*`, and TinyCLIP's LAION-400M models. LAION-400M was taken down together with LAION-5B in December 2023. I haven't confirmed a CSAM finding specific to LAION-400M from a primary source, so check that before relying on any LAION-400M model. TinyCLIP is distilled from larger CLIP teachers in any case, and the teachers' training data would also need checking.
- **SigLIP and OpenAI CLIP** fail the "disclosed enough to check" part of rule 2, because WebLI and OpenAI's crawl were never released.

### 1.1 Does DataComp-1B have documented CSAM findings or filtering?

I checked briefly, on 2026-11-25. **No CSAM finding has been documented for DataComp-1B or for the CommonPool it was filtered from. But nobody has reported checking either one against known-CSAM hash lists, and an independent audit says CSAM "cannot be ruled out".**

- **What DataComp did.** The [DataComp paper](https://arxiv.org/html/2304.14108) (Gadre et al., 2023) filtered CommonPool for NSFW content. Image NSFW used "a classifier on CLIP ViT-L/14 features, using the NSFW dataset used in LAION-5B". Text used Detoxify. "Around 19% of image-text pairs are considered NSFW" and were removed, and faces were blurred. The paper doesn't mention CSAM, PhotoDNA or hash matching.
- **What an independent audit found.** Hong, Agnew, Kohno and Morgenstern, ["Who's in and who's out?"](https://arxiv.org/abs/2405.08209) (EAAMO 2024), report that "the NSFW filter fails to remove sexually-explicit content from CommonPool". They estimate that 129–130 million of CommonPool's 12.8 billion samples come from sites Cloudflare classes as NSFW, and that 32–34 million of those would pass the CLIP filter. They call these "a substantial lower bound". On CSAM they say "we cannot assume that both CommonPool and CLIP-filtered CommonPool do not contain CSAM". They didn't run a hash match themselves, but they recommend that dataset creators "Run hash-based detection to known CSAM lists". The same group's later privacy audit, ["A Common Pool of Privacy Problems"](https://arxiv.org/abs/2506.17185) (2025), discusses CSAM only for LAION-5B, and it found that face blurring missed an estimated 102 million images with faces.
- **Result.** DataComp-1B passes rule 2 as written: it has no documented finding, and its data is disclosed (CommonPool's URLs are public, so a check is possible). The evidence isn't clear enough to change the recommendation. Before shipping, it would be worth asking a child-protection hotline to hash-match DataComp-1B's URLs, or finding out whether anyone already has.

**One new conflict, with rule 3.** DataComp-1B was *selected* with ImageNet. DataComp-1B is the "Image-based ∩ CLIP score (L/14 30%)" subset. Its image-based filter clusters the pool's image embeddings and keeps the clusters nearest to "every ImageNet training example". The model is trained on CommonPool images only, not on ImageNet images. But ImageNet decided which CommonPool images it saw. Whether that counts as "ImageNet-based" is the maintainer's call (open question 8 in section 3). If it does, the closest OpenCLIP checkpoints that avoid ImageNet entirely are the **CommonPool CLIP-score-filtered** ones: ViT-B/16 `commonpool_l_clip_s1b_b8k` (57.8% zero-shot on ImageNet, against 63.1% for the DataComp-1B-subset `datacomp_l_s1b_b8k` at the same scale) and ViT-L/14 `commonpool_xl_clip_s13b_b90k` (76.4%, but too large for the CPU budget). All are MIT ([`docs/datacomp_models.md`](https://github.com/mlfoundations/open_clip/blob/main/docs/datacomp_models.md)). Their CLIP-score filter uses OpenAI CLIP, which is a filtering tool here, not training data.

## 2. Recommendation

**Beta baseline (decided): Yahoo OpenNSFW (ResNet-50 "1by2"), which the project converts to ONNX from Yahoo's original Caffe file and quantizes to int8.** Of the candidates it is the only one where the licence on the weights is clear and on the allowlist (`BSD-2-Clause`), the weights come from the licensor's own repository, and the training data was not scraped from Reddit or a similar source. It is small (23.8 MB fp32, about 6–7 MB int8 *est.*), and every layer in it converts to a standard ONNX op. Its limits: it gives one score (pornographic or not), with no "suggestive" class, it dates from 2016, Yahoo published no accuracy figures, and nobody has published how it does on screenshots. Phase 0 has to measure that on Faro's own screenshot eval set before the beta.

**Long term: an OpenCLIP image encoder with MIT-licensed weights, trained on DataComp data, plus Faro's own linear heads.** Start with ViT-B-32 on DataComp-1B (`laion/CLIP-ViT-B-32-256x256-DataComp-s34B-b86K`, or `datacomp_xl_s13b_b90k` at 224 px), provided DataComp-1B's ImageNet-anchored selection is acceptable under rule 3 (section 1.1). If it isn't, use a CommonPool CLIP-score-filtered checkpoint instead. The best one at a CPU-friendly size is the ViT-B/16. The only B/32 trained on CommonPool CLIP-filtered data is the medium-scale one (27.3% zero-shot on ImageNet), so a B/32 encoder might mean Faro training its own on CommonPool. **MobileCLIP no longer qualifies.** Apple relicensed every MobileCLIP and MobileCLIP2 checkpoint under the *Apple Machine Learning Research Model* licence, which allows only "non-commercial scientific research" (on Hugging Face on 2025-02-28 and on GitHub on 2025-08-29).

Only the image encoder ships. The heads are a few kilobytes each, and the text encoder stays offline (it is only useful for zero-shot prototyping). **The hard part of the long-term option is the data for training the heads**, which is deferred until after the beta (decision 4).

**Rejected:**
- Every NudeNet version: GPL-3.0 for v1–v2, and AGPL-3.0 for v3 by the maintainer's own statement. v1–v2 were trained on a dataset in which the Canadian Centre for Child Protection found child sexual abuse material.
- MobileCLIP and MobileCLIP2: research-only licence.
- The models excluded by the decisions in section 1.

## 3. Open questions

Questions 1–7 were put to the maintainer, and the answers are in section 1. Question 8 is new: it came out of the DataComp-1B check.

1. ~~**How much training-data risk is acceptable?**~~ **Answered:** no model trained on a dataset with documented CSAM, and training data must be disclosed enough to check this (decision 2). *Original question:* no candidate has training data that is both disclosed and licensed for this use. NudeNet's dataset and LAION-5B are the only two with a documented CSAM finding, and they are also the only two with a published outside audit.
2. ~~**Where does the data for training Faro's own heads come from?**~~ **Answered:** deferred until after the beta (decision 4). It still needs a lawful source of adult images, a CSAM screening plan (for example hash matching through a hotline partner), and labellers.
3. ~~**ImageNet pretraining.**~~ **Answered:** allowed for the beta baseline only, and long-term models must not be ImageNet-based (decision 3). ImageNet's terms of access limit *the images* to "non-commercial research and educational purposes". OpenNSFW relies on its weights' own licence.
4. **Model-card scope statements.** *Follow-up for the task that ships the model (decision 5).* OpenAI's CLIP model card, and the LAION model cards that copy it, say "**Any** deployed use case of the model - whether commercial or not - is currently out of scope". That is guidance, not a licence term (the licences are MIT). The DataComp model cards carry the same text.
5. **Attribution in the update bundle.** *Follow-up for the task that ships the model (decision 5).* BSD-2-Clause and MIT both require shipping the copyright notice with binary redistributions, and `ModelInfo` carries only an SPDX `license` field. OpenNSFW needs this for the beta: "Copyright 2016, Yahoo Inc." plus the licence text.
6. ~~**Update ARCHITECTURE.md §3.5.**~~ **Answered:** done in this PR. §3.5 now names OpenNSFW as the beta baseline, drops MobileCLIP, excludes NudeNet, states the training-data rule and links this memo.
7. ~~**Faro's own licence.**~~ **Answered:** PR #22 rewrites §11, and this PR leaves §11 alone (decision 6).
8. **New: does DataComp-1B count as "ImageNet-based"?** Its weights were never trained on ImageNet images, but ImageNet's training images chose which CommonPool images went in (section 1.1). If that is acceptable, the long-term default stays DataComp-1B. If not, it moves to CommonPool CLIP-score-filtered data.

## 4. Comparison

### 4.1 Licences

"Allowlist" means the weights' licence is in `ALLOWED_MODEL_LICENSES` (`crates/faro-detect/src/classifier.rs`).

| Candidate | Weights licence | Code licence | Training data and its terms | Allowlist | Flags |
|---|---|---|---|---|---|
| **OpenNSFW** (Yahoo) | BSD-2-Clause (repo `LICENSE.md`, which covers "source and binary forms"; the weights are in the repo) | BSD-2-Clause | Yahoo-internal, "editorially labelled", not released. Pretrained on ImageNet-1k. | **Yes** | README says "Code licensed under the BSD 2 clause"; no separate weights statement. Repo archived. |
| **NudeNet v1** (2019) | GPL-3.0 (repo `LICENSE`; PyPI "GPLv3") | GPL-3.0 | NudeNet classifier dataset (scraped; **CSAM found by C3P**); detector v1 on 12,000 images "labelled by the good folks at cti-community" | No | Copyleft; contaminated data |
| **NudeNet v2** (2020–21) | GPL-3.0 (same) | GPL-3.0 | Classifier: same dataset. Detector: 160,000 images "auto-labelled", taken from that dataset | No | Copyleft; contaminated data |
| **NudeNet v3** (2023–24: 320n, 640m) | **Conflicting:** repo AGPL-3.0 since 2023-11-06; PyPI 3.4.2 says MIT; the maintainer says "it has to be AGPL" because it is built on YOLOv8 | AGPL-3.0 (repo) | Undisclosed; several open issues ask (#200, #161, #192) | No | Treat as AGPL. Ultralytics sells an enterprise licence; NudeNet doesn't. |
| **Falconsai/nsfw_image_detection** | Apache-2.0 (model-card YAML metadata only) | n/a | "proprietary dataset ... approximately 80,000 images", undisclosed; base model `google/vit-base-patch16-224-in21k` (Apache-2.0, ImageNet-21k) | Yes, nominally | No `LICENSE` file. The repo also holds a `falconsai_yolov9_nsfw_model_quantized.pt` of unstated lineage (upstream YOLOv9 is GPL-3.0; Ultralytics' is AGPL-3.0) |
| **GantMan/nsfw_model** | MIT ("Except where otherwise explicitly stated") | MIT | Scraped with `nsfw_data_scraper` (MIT scripts; "the source URLs are mostly links to various subreddits"); images not licensed; no audit known. Base: TF Hub MobileNetV2 / Inception V3 (ImageNet) | Yes | Weights are in release assets and on S3, not in the tree; MIT is read as covering them; README: "Please feel free to use this model to help your products!" |
| **MobileCLIP / MobileCLIP2** (Apple) | **Apple ML Research Model licence: research only** (since 2025) | MIT | DataCompDR (Hugging Face: `apple-amlr`; repo `LICENSE_DATA`: CC-BY-NC-ND-4.0) | **No** | Was the permissive Apple Sample Code License in 2024; relicensed |
| **OpenCLIP** (code) | varies per checkpoint | MIT | varies | — | MetaCLIP and NLLB-CLIP: CC-BY-NC; DFN: Apple AMLR; SigLIP: Apache-2.0; LAION/DataComp: MIT |
| OpenCLIP ViT-B-32 `laion2b_s34b_b79k` | MIT | MIT | LAION-2B-en (subset of LAION-5B; CSAM links found 2023, cleaned set "Re-LAION-5B" 2024) | Yes | Card: deployed use "out of scope". **Refused (decision 2)** |
| OpenCLIP ViT-B-32-256 / B-16, DataComp | MIT | MIT | DataComp-1B / XL from CommonPool (metadata CC-BY-4.0; "individual images are under their own copyrights"); NSFW-filtered (an audit found the filter leaky), faces blurred; no documented CSAM finding, and no published hash check | Yes | Same card language. DataComp-1B was selected using ImageNet (section 1.1) |
| OpenAI CLIP ViT-B/32 | MIT (repo) | MIT | Undisclosed web crawl; "will not be releasing the dataset" | Yes | Card: deployed use "out of scope". **Fails the disclosure part of decision 2** |
| TinyCLIP (Microsoft) | MIT (official repo; HF mirror tagged MIT) | MIT | LAION-400M or YFCC-15M, distilled from larger CLIP models | Yes | The checkpoints are hosted in `wkcn/TinyCLIP-model-zoo`, which has no licence file. **Refused (decision 2)**: LAION-400M data and LAION-trained teachers |
| SigLIP ViT-B/16 (Google) | Apache-2.0 | Apache-2.0 | WebLI, unreleased | Yes | Heavier compute. **Fails the disclosure part of decision 2** |

### 4.2 Fit

Sizes are file sizes from the listings; int8 sizes are *est.* (roughly 1 byte per parameter plus a little overhead). "Fits `ModelInfo`" means a single-tensor classifier whose output is a score vector, which is what `faro-detect` loads today.

| Candidate | Architecture | Input | Outputs | fp32 size | int8 (*est.*) | ONNX | Fits `ModelInfo` |
|---|---|---|---|---|---|---|---|
| OpenNSFW | ResNet-50 1by2 (half-width ResNet-50) | 224×224 BGR, Caffe mean | 2 (softmax: SFW, NSFW) | 23.8 MB `.caffemodel` | 6–7 MB | Not published. All 9 layer types are standard (Convolution, BatchNorm, Scale, ReLU, Eltwise, Pooling, InnerProduct, Softmax, Input). | Yes: `channel_order: bgr`, `input_scale: 1.0`, `output: probabilities` |
| NudeNet v2 classifier | Xception (per UnsafeBench) | 256×256 | 2 | 83.6 MB `.onnx` | ~21 MB | Published | Yes (licence rules it out) |
| NudeNet v2 detector | RetinaNet ResNet-50 | not stated | boxes, 16 classes | ~146 MB `.onnx` | ~37 MB | Published | No (detector) |
| NudeNet v3 320n / 640m | YOLOv8n / YOLOv8m | 320 / 640 | boxes, 18 classes | 12.2 / 103.5 MB `.onnx` | 3–4 / ~26 MB | Published (plus a separate NMS graph) | No: needs YOLO decoding and NMS, or a wrapper graph |
| Falconsai | ViT-B/16 (86M params) | 224×224, RGB, mean and std 0.5 | 2 (`normal`, `nsfw`) | 343 MB safetensors | ~88 MB | Not published; the standard HF ViT exports through Optimum | Yes |
| GantMan 1.2.0 | MobileNetV2 1.4 (TF Hub `mobilenet_v2_140_224`) | 224×224 | 5 (drawings, hentai, neutral, porn, sexy) | ~17 MB *est.* (release zip of several formats: 100.6 MB) | ~5 MB | Not published; Keras/SavedModel → `tf2onnx` | Yes: `layout: nhwc` or transpose at export |
| GantMan 1.0 | Inception V3 | 299×299 | 5 | ~87 MB *est.* | ~22 MB | Same | Yes |
| MobileCLIP-S0 (for reference) | MCi0 image encoder, 11.4M params | 256×256 | 512-d embedding | 216 MB checkpoint (both towers) | ~12 MB image tower | Not checked | Licence rules it out |
| OpenCLIP ViT-B-32 (image tower) | ViT-B/32, 87.9M params | 224 (or 256 for the DataComp B-32-256) | 512-d embedding → heads | ~351 MB *est.* (full checkpoint 605 MB) | ~90 MB | Standard transformer ops; exporting is routine, but I haven't verified it here | Yes, as encoder + heads in one graph with `output: sigmoid` |
| TinyCLIP ViT-40M/32 (image tower) | ViT, ~40M params | 224 | embedding | ~160 MB *est.* (full checkpoint 337 MB) | ~40 MB | As above | Yes |
| SigLIP ViT-B/16 (image tower) | ViT-B/16, ~93M params | 224 | 768-d embedding | ~370 MB *est.* (full checkpoint 813 MB) | ~95 MB | As above | Yes |

For compute: OpenCLIP's own profile lists 8.8 image GFLOPs for ViT-B-32 at 224 px and 35.1 for ViT-B-16, so a B/16 encoder (SigLIP included) costs about 4× a B/32 one. Against §3.5's target of under 80 ms per frame on CPU, B/32 is probably the realistic ceiling, and B/16 would probably need CoreML or DirectML. Nobody has measured any of these on Faro's hardware.

### 4.3 Accuracy, and what anyone knows about screenshots

| Candidate | Reported accuracy (source) | Screenshots |
|---|---|---|
| OpenNSFW | None in the repository. The README says: "We do not provide any guarantees of accuracy of output" and advises building your own eval set and fitting an ROC curve. (The linked Yahoo blog post returned HTTP 403.) | None published. The README excludes "sketches, cartoons, text, images of graphic violence". |
| NudeNet v2 classifier | UnsafeBench (independent, CCS 2025), Sexual category F1: 0.650 on real-world images, 0.596 on AI-generated | None |
| NudeNet v3 | No published metrics | None |
| Falconsai | `eval_accuracy: 0.980375` on a held-out split of its own undisclosed data | None |
| GantMan | "93% Accuracy" on its own test split (confusion matrix in the repo); NSFWJS: "~90% with small and ~93% with midsized model" | None |
| LAION CLIP NSFW detector (an MLP head on CLIP embeddings, MIT) | UnsafeBench, Sexual F1: 0.783 real-world, 0.678 AI-generated | None |
| CLIP backbones | Zero-shot ImageNet (OpenCLIP table); nothing NSFW-specific | None |

**I found no published evaluation of any candidate on screenshots** (UI chrome, text, video players, thumbnail grids). The closest is UnsafeBench's finding that performance drops as "grid size" increases, which is relevant to pages of thumbnails. It evaluated NudeNet's v2 binary classifier and the LAION CLIP detector, not OpenNSFW, GantMan or Falconsai. So §3.5's screenshot eval set is not a nice-to-have: it is the only evidence Faro will have. A useful side result from the same paper: on the Sexual category, both filters that work on CLIP embeddings (Stable Diffusion's safety checker, overall F1 0.785, and LAION's detector, 0.738) beat NudeNet's dedicated classifier (0.624). That supports the long-term encoder-plus-heads design.

---

## 5. Per-model detail

### 5.1 OpenNSFW (Yahoo)

- **Licence.** [`LICENSE.md`](https://github.com/yahoo/open_nsfw/blob/master/LICENSE.md): "Copyright 2016, Yahoo Inc. Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met: … 2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution." That is BSD-2-Clause word for word. The weights ([`nsfw_model/resnet_50_1by2_nsfw.caffemodel`](https://github.com/yahoo/open_nsfw/tree/master/nsfw_model), 23,815,355 bytes, in the initial commit of 2016-09-17) are in the same repository, and the licence has no exception for them.
- **Ambiguity, minor.** The [README](https://github.com/yahoo/open_nsfw/blob/master/README.md) says "Code licensed under the [BSD 2 clause license]". It doesn't name the weights. Because the weights are in the repository and the licence file has no carve-out, the reasonable reading is that BSD-2-Clause covers them, and ARCHITECTURE §3.5 already reads it that way. The repository is archived (last push 2018-11-21), so there is nobody to ask.
- **Training data.** README: "We trained the model on the dataset with NSFW images as positive and SFW … images as negative. These images were editorially labelled. We cannot release the dataset or other details due to the nature of the data." It was pretrained on ImageNet-1k (see open question 3). Nothing is published about how the data was collected or screened.
- **Architecture and preprocessing.** The [`deploy.prototxt`](https://github.com/yahoo/open_nsfw/blob/master/nsfw_model/deploy.prototxt) shows a 1×3×224×224 input and 53 convolutions with BatchNorm and Scale, 16 residual adds, 2 pooling layers, one fully connected layer and a softmax. Yahoo's [`classify_nsfw.py`](https://github.com/yahoo/open_nsfw/blob/master/classify_nsfw.py) resizes to 256×256 (bilinear), re-encodes as JPEG, then centre-crops to 224. Faro's `preprocess` resizes straight to `input_size` with no crop unless the manifest sets `resize` to `resize_crop` (Yahoo's resize and crop, without the JPEG step), and `model-bench --resize direct,resize_crop:256` compares the two, so the eval should check whether that matters (DEVELOPMENT.md, "Comparing preprocessing").
- **Export.** There is no ONNX file upstream. Two routes: (a) read the `.caffemodel` protobuf directly into a PyTorch copy of the network and export it, which needs no Caffe install and starts from Yahoo's own file; (b) use the MIT-licensed Keras port [`bhky/opennsfw2`](https://github.com/bhky/opennsfw2), whose weights file comes from that project's own release, then `tf2onnx`. Route (a) gives the cleaner provenance; route (b) is useful for checking parity. Watch Caffe's pooling rounding (ONNX `ceil_mode`).
- **Fit.** Two outputs (SFW, NSFW) map to `explicit`; there is no `suggestive`. Yahoo's own guidance: "Scores < 0.2 indicate that the image is likely to be safe with high probability. Scores > 0.8 indicate that the image is highly probable to be NSFW."

### 5.2 NudeNet (notAI-tech), each version

The licence history, from the repository's own commits:

| Period | Repo licence file | PyPI metadata | Models |
|---|---|---|---|
| 2019-03-29 → 2022-11-01 | `LICENSE`: GNU GPL v3 ([at v2.0.9](https://github.com/notAI-tech/NudeNet/blob/v2.0.9/LICENSE)) | 1.x–2.0.9: "GPLv3" | v1 and v2 classifiers and detectors (release [`v0`](https://github.com/notAI-tech/NudeNet/releases/tag/v0), 2019-12-19) |
| 2022-11-01 → 2023-11-06 | `LICENSE.md`: MIT, "Copyright (c) 2022 notAI.tech" ([commit 309ecb5](https://github.com/notAI-tech/NudeNet/commit/309ecb5060ce849c1bd731f338f5bff5f4a89e31)) | 3.0.x: "MIT" | v3 YOLOv8n detector |
| 2023-11-06 → today | `LICENSE` and `LICENSE.md`: GNU AGPL v3 ([commit b5e7fa8](https://github.com/notAI-tech/NudeNet/commit/b5e7fa859f43594f72a13a34c60a06d8343105f5)) | 3.4.x: still "MIT" (`setup.py`: `license="MIT"`) | [`v3.2-weights`](https://github.com/notAI-tech/NudeNet/releases/tag/v3.2-weights) (2024-06-15), [`v3.4-weights`](https://github.com/notAI-tech/NudeNet/releases/tag/v3.4-weights) (2024-06-30): 320n, 640m |

- **Why AGPL.** In [#119](https://github.com/notAI-tech/NudeNet/issues/119#issuecomment-1795734430) a user pointed out that "Yolov8 has a GNU license", and the maintainer replied "changed" (2023-11-06). In [#177](https://github.com/notAI-tech/NudeNet/issues/177#issuecomment-3720339648), answering the PyPI/repo mismatch, the maintainer wrote (2026-01-07): "since yolov8 is used, it has to be AGPL I believe. Pypi license was added before yolov8 with retinanet. I will update on pypi." PyPI had not been updated by 2026-11-25. Ultralytics' [README](https://github.com/ultralytics/ultralytics#-license) offers AGPL-3.0 or an "Enterprise License" for "integration of Ultralytics software and AI models into business products". Issues [#197](https://github.com/notAI-tech/NudeNet/issues/197), [#198](https://github.com/notAI-tech/NudeNet/issues/198) and [#204](https://github.com/notAI-tech/NudeNet/issues/204) asking for a non-AGPL licence for the weights had no reply.
- **Training data.** The v2 [README](https://github.com/notAI-tech/NudeNet/blob/v2.0.9/README.md): "V2 (current version) of NudeDetector is trained on 160,000 entirely auto-labelled … images", "The entire data for the classifier is available at https://archive.org/details/NudeNet_classifier_dataset_v1", and the detector's auto-labelled data uses "Images … from the classifier dataset above". On 2025-10-22 the Canadian Centre for Child Protection [reported](https://protectchildren.ca/en/press-and-media/news-releases/2025/csam-nude-net) that "the NudeNet dataset, contains more than 700,000 images" and that its analysis "surfaced nearly 680 images that C3P knows or suspects are child sexual abuse and exploitation material". It also found that 29 of 50 sampled projects "relied on the NudeNet classifier or model". The archive.org copy has been taken down ([#162](https://github.com/notAI-tech/NudeNet/issues/162)). On 2026-11-25 the `v0` release still listed `DETECTOR_AUTO_GENERATED_DATA.zip` (660 MB). For v3 the training data is not disclosed, and [#200](https://github.com/notAI-tech/NudeNet/issues/200) asks about its provenance, with no answer.
- **Fit.** v3 is a detector (boxes for 18 classes such as `FEMALE_BREAST_EXPOSED`) at 320 or 640 px, not a classifier, so it would need postprocessing to fit `ModelInfo`.
- **Verdict.** Excluded on licence (GPL-3.0 or AGPL-3.0) for every version, and on data provenance for v1–v2 regardless of licence. This answers §3.5's "check NudeNet's terms specifically".

### 5.3 Falconsai/nsfw_image_detection

- **Licence.** The [model card](https://huggingface.co/Falconsai/nsfw_image_detection/blob/main/README.md) front matter has `license: apache-2.0`. The repository has no `LICENSE` file and no copyright line ([file list](https://huggingface.co/Falconsai/nsfw_image_detection/tree/main): `model.safetensors` 343,223,968 bytes, `pytorch_model.bin`, `optimizer.pt`, `config.json`, `labels.json`, and `falconsai_yolov9_nsfw_model_quantized.pt` 87,132,571 bytes). The base model, [`google/vit-base-patch16-224-in21k`](https://huggingface.co/google/vit-base-patch16-224-in21k), is Apache-2.0.
- **Ambiguity.** A metadata tag is a weaker grant than a licence file, but it is the only one Hugging Face offers, and the Apache-2.0 text is standard. The YOLOv9 file was added on 2025-04-06 under the same tag, and the card doesn't say which YOLOv9 it comes from (upstream [WongKinYiu/yolov9](https://github.com/WongKinYiu/yolov9) is GPL-3.0, Ultralytics' is AGPL-3.0). Faro would use only the ViT weights, but the tag can't be relied on for the YOLO file.
- **Training data.** "a proprietary dataset comprising approximately 80,000 images … two distinct classes: 'normal' and 'nsfw'." Nothing about where it came from.
- **Accuracy.** `eval_accuracy: 0.980375` on an undisclosed split.
- **Architecture.** `ViTForImageClassification`, 12 layers, hidden size 768, patch 16, 224 px, labels `normal`/`nsfw` ([`config.json`](https://huggingface.co/Falconsai/nsfw_image_detection/blob/main/config.json)). It exports to ONNX through Optimum. Expect about 88 MB at int8 *est.* and about 4× OpenNSFW's compute.

### 5.4 GantMan/nsfw_model (and NSFWJS)

- **Licence.** [`LICENSE.md`](https://github.com/GantMan/nsfw_model/blob/master/LICENSE.md): "This project contains third-party copyrighted material under different licenses. Except where otherwise explicitly stated, this project is licensed as follows: MIT License Copyright (c) 2020 The nsfw_model Developers". No file says what the "third-party copyrighted material" is. The 1.2.0 weights are a release asset ([`mobilenet_v2_140_224.1.zip`](https://github.com/GantMan/nsfw_model/releases/tag/1.2.0), 100,619,093 bytes, 2020-05-15). The 1.0 weights are on Infinite Red's S3. The README invites product use: "Please feel free to use this model to help your products!" The same models ship inside [NSFWJS](https://github.com/infinitered/nsfwjs) (MIT, maintained) as `mobilenet_v2`, `mobilenet_v2_mid` and `inception_v3`.
- **Training data.** README: "Special thanks to the [nsfw_data_scraper](https://github.com/alex000kim/nsfw_data_scraper) for the training data." That scraper's [README](https://github.com/alex000kim/nsfw_data_scraper/blob/master/README.md): "The source URLs are mostly links to various subreddits", plus Danbooru2018 and Caltech256 for the safe classes, and "use with caution - the dataset is noisy". The MIT licence covers the scripts, not the images. I found no audit of this data.
- **Architecture.** The 1.2.0 model comes from `training/make_nsfw_model.py` on TF Hub's MobileNetV2 feature vector at 224 px. The 1.0 model is Inception V3 at 299 px. Both have five softmax classes. Exported with `tf2onnx`, both are standard graphs.
- **Accuracy.** "93% Accuracy" (Inception V3, its own test split).
- **Fit.** The best class match for Faro (`porn` and `hentai` map to explicit, `sexy` to suggestive), at about the same size as OpenNSFW.

### 5.5 MobileCLIP and MobileCLIP2 (Apple)

- **Licence now.** [`LICENSE_MODELS`](https://github.com/apple/ml-mobileclip/blob/main/LICENSE_MODELS): Apple "grants you a personal, non-exclusive, worldwide, non-transferable, royalty-free, revocable, and limited license … exclusively for Research Purposes. You agree that any Model Derivatives You may create … will be limited to Research Purposes as well. 'Research Purposes' means non-commercial scientific research … 'Research Purposes' does not include any commercial exploitation, product development or use in any commercial product or service." "Model Derivatives" includes "any retraining, fine-tuning". So linear heads on MobileCLIP features are arguably covered too, and in any case Faro would redistribute the encoder.
- **History.** At first release (2024-03) the repository's only `LICENSE` was the Apple Sample Code License. From 2024-07-22 the weights and data were under that licence in `LICENSE_weights_data` ([commit 341ef05](https://github.com/apple/ml-mobileclip/commit/341ef058802f0e4e5ab13c02f0cb32a3a94e367b)), which allowed redistribution "with or without modifications". On Hugging Face the checkpoints moved to AMLR on 2025-02-28 ([e.g. MobileCLIP-S0, "AMLR license (#2)"](https://huggingface.co/apple/MobileCLIP-S0/commit/97cfce8bab0459233841c01dd4ab6ac5c167f543)). On GitHub `LICENSE_weights_data` was replaced by `LICENSE_MODELS` (AMLR) and `LICENSE_DATA` (CC-BY-NC-ND-4.0) on 2025-08-29 ([commit e15d36e](https://github.com/apple/ml-mobileclip/commit/e15d36effd4cd9832b25f5c0063a5b8b279826cd)). The code stays MIT.
- **Inconsistency.** The [`MobileCLIP-S1`](https://huggingface.co/apple/MobileCLIP-S1/blob/main/README.md) and S2 cards still say `license_name: apple-ascl` with a `license_link` to the deleted `LICENSE_weights_data`, next to `license: apple-amlr`. Their `LICENSE` files are AMLR. The `timm/MobileCLIP2-*-OpenCLIP` copies are also tagged `apple-amlr`.
- **Verdict.** Excluded. A copy downloaded in 2024 under the old licence would be on firmer ground, but relying on a revoked grant for a project-signed, widely redistributed model is not worth it, and it would not cover MobileCLIP2. Apple's DFN CLIP models are AMLR too.

### 5.6 OpenCLIP and other CLIP-style backbones

- **Code.** [OpenCLIP](https://github.com/mlfoundations/open_clip/blob/main/LICENSE) is MIT. Each checkpoint has its own licence. [`docs/PRETRAINED.md`](https://github.com/mlfoundations/open_clip/blob/main/docs/PRETRAINED.md): MetaCLIP "Models are licensed under CC-BY-NC", NLLB-CLIP "CC-BY-NC", CLIPA "Apache 2.0", SigLIP "Apache 2 license", DFN under Apple's licence. The LAION and DataComp checkpoints on Hugging Face are tagged `license: mit` ([ViT-B-32 LAION-2B](https://huggingface.co/laion/CLIP-ViT-B-32-laion2B-s34B-b79K), [ViT-B-32-256 DataComp](https://huggingface.co/laion/CLIP-ViT-B-32-256x256-DataComp-s34B-b86K), [ViT-B-16 DataComp.XL](https://huggingface.co/laion/CLIP-ViT-B-16-DataComp.XL-s13B-b90K)).
- **LAION-2B data.** The card warns: "this large-scale dataset is uncurated … we however do not recommend using it for creating ready-to-go industrial products". In December 2023 the Stanford Internet Observatory [reported](https://purl.stanford.edu/kh752sm9123) CSAM in LAION-5B. LAION's [Re-LAION-5B post](https://laion.ai/blog/relaion-5b/) (2024-08-30) says "Stanford reportedly identified 1008 links" and "In all, 2236 links were removed". It doesn't say anything about models trained on the original data. (I read LAION's post, not the Stanford report itself. Press coverage says the report's recommendation to deprecate models was aimed at Stable Diffusion 1.5.) The OpenCLIP LAION-2B checkpoints were trained on the original set.
- **DataComp data.** The [dataset card](https://huggingface.co/datasets/mlfoundations/datacomp_pools/blob/main/README.md): "We distribute the image url-text samples and metadata under a standard Creative Common CC-BY-4.0 license. The individual images are under their own copyrights." The [paper](https://arxiv.org/html/2304.14108) says "we train a classifier on CLIP ViT-L/14 features, using the NSFW dataset used in LAION-5B", that "Around 19% of image-text pairs are considered NSFW" and were removed, and "we detect and blur faces". The paper doesn't mention CSAM. An independent audit found that the NSFW filter misses a good deal of explicit content (section 1.1), so how well a DataComp encoder separates explicit from suggestive has to be measured, not assumed. DataComp-1B's ImageNet-anchored selection is also covered in section 1.1.
- **OpenAI CLIP.** [Repository](https://github.com/openai/CLIP) MIT. [Model card](https://github.com/openai/CLIP/blob/main/model-card.md): "we only crawled websites that had policies against excessively violent and adult images", "will not be releasing the dataset", and "**Any** deployed use case of the model - whether commercial or not - is currently out of scope."
- **TinyCLIP.** [microsoft/Cream](https://github.com/microsoft/Cream/tree/main/TinyCLIP) (MIT). Zero-shot ImageNet: ViT-40M/32 (LAION-400M) 59.8%, ViT-61M/32 62.4%, ViT-8M/16 (YFCC-15M) 41.1%. The checkpoints are linked from [`wkcn/TinyCLIP-model-zoo`](https://github.com/wkcn/TinyCLIP-model-zoo), which has no licence file; the Hugging Face mirrors (`wkcn/TinyCLIP-*`) are tagged MIT. YFCC images carry their own per-image Creative Commons licences, some of them non-commercial.
- **SigLIP.** [`google/siglip-base-patch16-224`](https://huggingface.co/google/siglip-base-patch16-224) and [`timm/ViT-B-16-SigLIP`](https://huggingface.co/timm/ViT-B-16-SigLIP) are Apache-2.0 ([big_vision](https://github.com/google-research/big_vision) is Apache-2.0 too). WebLI isn't released. The smallest SigLIP and SigLIP 2 image towers are B/16, which is about 4× the compute of B/32.
- **An existing permissive head.** LAION's [CLIP-based-NSFW-Detector](https://github.com/LAION-AI/CLIP-based-NSFW-Detector) ships small Autokeras heads for CLIP ViT-L/14 and ViT-B/32 embeddings under MIT ("This code and model is released under the MIT license"), plus a "manually annotated" test set. Its training embeddings are "not fully manually annotated". In UnsafeBench it was second on the Sexual category, behind Stable Diffusion's safety checker and well ahead of NudeNet. It is refused under decision 2, because its training embeddings come from LAION data, but it shows that a head on CLIP embeddings works.

---

## 6. Sources

All checked on 2026-11-25.

- Yahoo OpenNSFW: <https://github.com/yahoo/open_nsfw> (`LICENSE.md`, `README.md`, `nsfw_model/`, `classify_nsfw.py`)
- opennsfw2: <https://github.com/bhky/opennsfw2>
- NudeNet: <https://github.com/notAI-tech/NudeNet> (licence history, releases, issues #119, #161, #162, #177, #192, #197, #198, #200, #204); PyPI <https://pypi.org/project/nudenet/>
- Canadian Centre for Child Protection, 2025-10-22: <https://protectchildren.ca/en/press-and-media/news-releases/2025/csam-nude-net>
- Ultralytics licence: <https://github.com/ultralytics/ultralytics#-license>; YOLOv9: <https://github.com/WongKinYiu/yolov9>
- Falconsai: <https://huggingface.co/Falconsai/nsfw_image_detection>; base <https://huggingface.co/google/vit-base-patch16-224-in21k>
- GantMan: <https://github.com/GantMan/nsfw_model>; NSFWJS <https://github.com/infinitered/nsfwjs>; data <https://github.com/alex000kim/nsfw_data_scraper>
- MobileCLIP: <https://github.com/apple/ml-mobileclip> (`LICENSE`, `LICENSE_MODELS`, `LICENSE_DATA`, history); <https://huggingface.co/apple/MobileCLIP-S0> and siblings
- OpenCLIP: <https://github.com/mlfoundations/open_clip> (`LICENSE`, `docs/PRETRAINED.md`, `docs/model_profile.csv`); LAION and DataComp checkpoints on Hugging Face as linked above
- DataComp: <https://arxiv.org/html/2304.14108>; <https://huggingface.co/datasets/mlfoundations/datacomp_pools>; <https://github.com/mlfoundations/open_clip/blob/main/docs/datacomp_models.md>
- DataComp audits: Hong et al., "Who's in and who's out?" (EAAMO 2024) <https://arxiv.org/abs/2405.08209>; Hong et al., "A Common Pool of Privacy Problems" (2025) <https://arxiv.org/abs/2506.17185>
- LAION: <https://laion.ai/blog/relaion-5b/>; Stanford Internet Observatory report <https://purl.stanford.edu/kh752sm9123> (not read in full)
- OpenAI CLIP: <https://github.com/openai/CLIP>
- TinyCLIP: <https://github.com/microsoft/Cream/tree/main/TinyCLIP>
- SigLIP: <https://huggingface.co/google/siglip-base-patch16-224>
- LAION CLIP-based NSFW detector: <https://github.com/LAION-AI/CLIP-based-NSFW-Detector>
- UnsafeBench (Qu et al., CCS 2025): <https://arxiv.org/abs/2405.03486>
- ImageNet terms of access, as reproduced on the gated Hugging Face mirror <https://huggingface.co/datasets/ILSVRC/imagenet-1k> ("Researcher shall use the Database only for non-commercial research and educational purposes."); image-net.org refused connections on the day of checking.

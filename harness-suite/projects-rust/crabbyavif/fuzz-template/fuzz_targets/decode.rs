#![no_main]
//! AVIF decode harness mirroring how Chromium's Blink AVIFImageDecoder
//! (third_party/blink/renderer/platform/image-decoders/avif/avif_image_decoder.cc)
//! drives CrabbyAvif through its C API (`capi` feature, dav1d + libyuv backends):
//!
//! - ignoreXMP / ignoreExif, strictFlags without CLAP_VALID and PIXI_REQUIRED
//! - non-persistent avifIO (Chromium uses a custom non-persistent reader)
//! - Parse, NthImageMaxExtent / NthImageTiming, NthImage for every frame
//! - clap handling via avifCropRectConvertCleanApertureBox + avifImageSetViewRect
//! - YUV -> 8-bit BGRA premultiplied (or RGBA half-float for >8-bit) via avifImageYUVToRGB
//! - a separate decoder with imageContentToDecode = GAIN_MAP when a gain map is present
//!
//! Deviations for wasm32-wasip1: maxThreads = 1 (Chromium uses 2; no threads on
//! wasip1), and lower image size / frame limits to keep memory and time bounded.

use crabby_avif::capi::decoder::*;
use crabby_avif::capi::image::*;
use crabby_avif::capi::io::*;
use crabby_avif::capi::reformat::*;
use crabby_avif::capi::types::*;
use crabby_avif::reformat::rgb;
use libfuzzer_sys::fuzz_target;

const IMAGE_SIZE_LIMIT: u32 = 4096 * 4096;
const IMAGE_DIMENSION_LIMIT: u32 = 16384;
const MAX_FRAMES: i32 = 16;

unsafe fn render(image: *const avifImage, half_float: bool) {
    let img = &*image;
    let mut rgb_image: avifRGBImage = std::mem::zeroed();
    crabby_avifRGBImageSetDefaults(&mut rgb_image, image);
    let mut buf: Vec<u64>;
    if half_float {
        rgb_image.depth = 16;
        rgb_image.is_float = true;
        rgb_image.format = rgb::Format::Rgba;
        rgb_image.row_bytes = img.width * 8;
        buf = vec![0u64; img.width as usize * img.height as usize];
    } else {
        rgb_image.depth = 8;
        rgb_image.format = rgb::Format::Bgra;
        rgb_image.row_bytes = img.width * 4;
        buf = vec![0u64; (img.width as usize * img.height as usize).div_ceil(2)];
    }
    rgb_image.pixels = buf.as_mut_ptr() as *mut u8;
    rgb_image.alpha_premultiplied = true;
    rgb_image.max_threads = 1;
    let _ = crabby_avifImageYUVToRGB(image, &mut rgb_image);

    // Chromium renders incrementally decoded images in row ranges through a view.
    if img.height >= 2 {
        let view = crabby_avifImageCreateEmpty();
        let rect = avifCropRect { x: 0, y: 1, width: img.width, height: img.height - 1 };
        if crabby_avifImageSetViewRect(view, image, &rect) == avifResult::Ok {
            let _ = crabby_avifImageYUVToRGB(view, &mut rgb_image);
        }
        crabby_avifImageDestroy(view);
    }
}

unsafe fn decode(data: &[u8], gain_map: bool) -> bool {
    let decoder = crabby_avifDecoderCreate();
    if decoder.is_null() {
        return false;
    }
    let dec = &mut *decoder;
    dec.maxThreads = 1;
    dec.ignoreXMP = AVIF_TRUE;
    dec.ignoreExif = AVIF_TRUE;
    dec.strictFlags &= !AVIF_STRICT_CLAP_VALID;
    dec.strictFlags &= !AVIF_STRICT_PIXI_REQUIRED;
    dec.imageSizeLimit = IMAGE_SIZE_LIMIT;
    dec.imageDimensionLimit = IMAGE_DIMENSION_LIMIT;
    if gain_map {
        dec.imageContentToDecode = AVIF_IMAGE_CONTENT_GAIN_MAP;
    }
    let io = crabby_avifIOCreateMemoryReader(data.as_ptr(), data.len());
    crabby_avifDecoderSetIO(decoder, io);
    dec.allowProgressive = AVIF_FALSE;

    let mut has_gain_map = false;
    if crabby_avifDecoderParse(decoder) == avifResult::Ok && dec.imageCount > 0 {
        let container = &*dec.image;
        let mut format_info: avifPixelFormatInfo = std::mem::zeroed();
        crabby_avifGetPixelFormatInfo(container.yuvFormat, &mut format_info);
        has_gain_map = !container.gainMap.is_null();

        let mut crop: Option<avifCropRect> = None;
        if container.transformFlags & AVIF_TRANSFORM_CLAP != 0 {
            let mut rect: avifCropRect = std::mem::zeroed();
            let mut diag: avifDiagnostics = std::mem::zeroed();
            if crabby_avifCropRectConvertCleanApertureBox(
                &mut rect,
                &container.clap,
                container.width,
                container.height,
                container.yuvFormat,
                &mut diag,
            ) == AVIF_TRUE
            {
                crop = Some(rect);
            }
        }
        let half_float = container.depth > 8;

        let count = dec.imageCount.min(MAX_FRAMES);
        for index in 0..count {
            let mut extent: avifExtent = std::mem::zeroed();
            let _ = crabby_avifDecoderNthImageMaxExtent(decoder, index as u32, &mut extent);
            let mut timing: crabby_avif::decoder::track::ImageTiming = std::mem::zeroed();
            let _ = crabby_avifDecoderNthImageTiming(decoder, index as u32, &mut timing);
            if crabby_avifDecoderNthImage(decoder, index as u32) != avifResult::Ok {
                break;
            }
            let _ = crabby_avifDecoderDecodedRowCount(decoder);
            let _ = crabby_avifDecoderIsKeyframe(decoder, index as u32);
            let mut image: *const avifImage = dec.image;
            if gain_map {
                let gm = (*dec.image).gainMap;
                if gm.is_null() || (*gm).image.is_null() {
                    break;
                }
                image = (*gm).image;
            }
            let mut view = std::ptr::null_mut();
            if let Some(rect) = crop {
                view = crabby_avifImageCreateEmpty();
                if crabby_avifImageSetViewRect(view, image, &rect) == avifResult::Ok {
                    image = view;
                }
            }
            render(image, half_float && !gain_map);
            if !view.is_null() {
                crabby_avifImageDestroy(view);
            }
        }
    }
    crabby_avifDecoderDestroy(decoder);
    has_gain_map
}

fuzz_target!(|data: &[u8]| {
    unsafe {
        let ro = avifROData { data: data.as_ptr(), size: data.len() };
        let _ = crabby_avifPeekCompatibleFileType(&ro);
        if decode(data, false) {
            decode(data, true);
        }
    }
});

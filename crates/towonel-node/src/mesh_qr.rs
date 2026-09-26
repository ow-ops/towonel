//! Terminal QR code with the towonel logo in the middle.

use std::fmt::Write;

use qrcode::render::unicode::Dense1x2;
use qrcode::types::QrError;
use qrcode::{Color, EcLevel, QrCode};

type Rgb = [u8; 3];

const DARK: Rgb = [0x0c, 0x0a, 0x14];
const LIGHT: Rgb = [0xff, 0xff, 0xff];
const QUIET_ZONE: usize = 2;

/// Truecolor with the logo when the terminal supports it, plain blocks
/// otherwise.
pub fn render(url: &str) -> Result<String, QrError> {
    if truecolor() {
        let (grid, side) = logo_grid(url)?;
        Ok(to_ansi(&grid, side))
    } else {
        plain(url)
    }
}

fn truecolor() -> bool {
    std::env::var_os("NO_COLOR").is_none()
        && std::env::var("COLORTERM").is_ok_and(|v| v == "truecolor" || v == "24bit")
}

fn plain(url: &str) -> Result<String, QrError> {
    // Inverted so the code reads as dark-on-light on dark terminals.
    Ok(QrCode::new(url.as_bytes())?
        .render::<Dense1x2>()
        .dark_color(Dense1x2::Light)
        .light_color(Dense1x2::Dark)
        .build())
}

/// One pixel per module, quiet zone included. EC level H recovers the
/// modules the logo covers.
fn logo_grid(url: &str) -> Result<(Vec<Rgb>, usize), QrError> {
    let qr = QrCode::with_error_correction_level(url.as_bytes(), EcLevel::H)?;
    let width = qr.width();
    let side = width + 2 * QUIET_ZONE;
    let mut grid = vec![LIGHT; side * side];
    for (i, color) in qr.to_colors().into_iter().enumerate() {
        if color == Color::Dark
            && let Some(px) = grid.get_mut((i / width + QUIET_ZONE) * side + i % width + QUIET_ZONE)
        {
            *px = DARK;
        }
    }

    // Odd so it centres on the module grid; one light module of padding.
    let patch = (width / 3) | 1;
    let logo = patch - 2;
    let origin = (side - patch) / 2;
    for y in 0..patch {
        for x in 0..patch {
            let inside = (1..=logo).contains(&x) && (1..=logo).contains(&y);
            let color = if inside {
                logo_pixel(x - 1, y - 1, logo)
            } else {
                LIGHT
            };
            if let Some(px) = grid.get_mut((origin + y) * side + origin + x) {
                *px = color;
            }
        }
    }
    Ok((grid, side))
}

/// Two modules per character: `▀` with the top module as foreground.
fn to_ansi(grid: &[Rgb], side: usize) -> String {
    let at = |x: usize, y: usize| grid.get(y * side + x).copied().unwrap_or(LIGHT);
    let mut out = String::new();
    for y in (0..side).step_by(2) {
        for x in 0..side {
            let [tr, tg, tb] = at(x, y);
            let [br, bg, bb] = if y + 1 < side { at(x, y + 1) } else { LIGHT };
            #[expect(clippy::unwrap_used, reason = "writing to a String cannot fail")]
            write!(out, "\x1b[38;2;{tr};{tg};{tb}m\x1b[48;2;{br};{bg};{bb}m▀").unwrap();
        }
        out.push_str("\x1b[0m\n");
    }
    out
}

/// Pixel `(x, y)` of an `n`×`n` raster of the site logo (`favicon.svg`,
/// 32×32 viewBox), supersampled so the small orb survives.
fn logo_pixel(x: usize, y: usize, n: usize) -> Rgb {
    const SS: usize = 4;
    let mut sum = [0u32; 3];
    for sy in 0..SS {
        for sx in 0..SS {
            let to_svg = |p: usize, s: usize| {
                #[expect(clippy::cast_precision_loss, reason = "logo is a few dozen pixels")]
                let v = ((p * SS + s) as f32 + 0.5) * 32.0 / (n * SS) as f32;
                v
            };
            let c = logo_sample(to_svg(x, sx), to_svg(y, sy));
            for (acc, ch) in sum.iter_mut().zip(c) {
                *acc += u32::from(ch);
            }
        }
    }
    #[expect(clippy::cast_possible_truncation, reason = "average of u8 samples")]
    sum.map(|s| (s / (SS * SS) as u32) as u8)
}

fn logo_sample(x: f32, y: f32) -> Rgb {
    let dist = |cx: f32, cy: f32| (x - cx).hypot(y - cy);
    let arch = |left: f32, right: f32, spring: f32, radius: f32| {
        (left..=right).contains(&x) && y <= 27.0 && (y >= spring || dist(16.0, spring) <= radius)
    };

    let orb = dist(16.0, 16.6);
    if orb <= 2.7 {
        // radialGradient cx=50% cy=44% r=52% of the orb's 5.4-wide bounding box.
        let t = (dist(16.0, 16.276) / 2.808).min(1.0);
        return if t < 0.45 {
            lerp([0xf0, 0xeb, 0xfa], [0xc8, 0xb8, 0xec], t / 0.45)
        } else {
            lerp([0xc8, 0xb8, 0xec], [0x6e, 0x4f, 0xd1], (t - 0.45) / 0.55)
        };
    }
    if arch(11.0, 21.0, 16.0, 5.0) {
        return [0x2a, 0x21, 0x40];
    }
    if arch(8.0, 24.0, 15.5, 8.0) {
        return [0x0c, 0x0a, 0x14];
    }
    // Rounded square, rx = 8.
    let corner = |c: f32| c.clamp(8.0, 24.0);
    if dist(corner(x), corner(y)) <= 8.0 {
        [0xc8, 0xb8, 0xec]
    } else {
        LIGHT
    }
}

fn lerp(a: Rgb, b: Rgb, t: f32) -> Rgb {
    let mut out = [0u8; 3];
    for ((o, a), b) in out.iter_mut().zip(a).zip(b) {
        #[expect(
            clippy::cast_possible_truncation,
            clippy::cast_sign_loss,
            reason = "interpolates between two u8 channels"
        )]
        {
            *o = (f32::from(b) - f32::from(a))
                .mul_add(t, f32::from(a))
                .round() as u8;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const URLS: [&str; 2] = [
        "https://c.example/mesh/connect?code=BCDFGHJK",
        "https://console.towonel.example.com/mesh/connect?code=BCDFGHJK",
    ];

    /// Decode the rendered grid the way a phone would: via luminance.
    fn decode(grid: &[Rgb], side: usize) -> String {
        const SCALE: usize = 6;
        let px = side * SCALE;
        let mut img = rqrr::PreparedImage::prepare_from_greyscale(px, px, |x, y| {
            let [r, g, b] = grid[(y / SCALE) * side + x / SCALE];
            let lum = (u32::from(r) * 299 + u32::from(g) * 587 + u32::from(b) * 114) / 1000;
            u8::try_from(lum).unwrap()
        });
        let grids = img.detect_grids();
        assert_eq!(grids.len(), 1);
        grids[0].decode().unwrap().1
    }

    #[test]
    fn logo_qr_still_decodes() {
        for url in URLS {
            let (grid, side) = logo_grid(url).unwrap();
            assert_eq!(decode(&grid, side), url);
        }
    }

    #[test]
    fn logo_is_drawn_in_the_centre() {
        let (grid, side) = logo_grid(URLS[1]).unwrap();
        let centre = grid[(side / 2) * side + side / 2];
        assert!(centre != DARK && centre != LIGHT, "centre is {centre:?}");
    }

    #[test]
    fn ansi_has_two_rows_per_line() {
        let (grid, side) = logo_grid(URLS[0]).unwrap();
        let out = to_ansi(&grid, side);
        assert_eq!(out.lines().count(), side.div_ceil(2));
        assert!(out.lines().all(|l| l.matches('▀').count() == side));
    }

    #[test]
    fn plain_is_square() {
        let qr = plain(URLS[0]).unwrap();
        let lines: Vec<&str> = qr.lines().collect();
        let width = lines[0].chars().count();
        assert!(lines.iter().all(|l| l.chars().count() == width));
        assert!(lines.len() * 2 >= width && lines.len() * 2 <= width + 2);
    }
}

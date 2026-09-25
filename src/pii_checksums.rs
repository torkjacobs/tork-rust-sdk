//! Check digits for the country registry.
//!
//! The SDK bundle NAMES twenty algorithms and gives weights and a modulus for
//! the eleven that reduce to them; the other nine are marked `kind: "custom"`
//! and carry no specification, so they are ported here by hand from the cloud's
//! `lib/pii/checksums.ts` -- the single implementation the cloud and the country
//! corpus both use. Keeping the arithmetic identical is what makes a receipt
//! block from this SDK byte-identical to one from the JavaScript SDK.
//!
//! Every function is pure: a `&str` in, a `bool` out. No I/O, no clock.

fn digits_of(s: &str) -> String {
    s.chars().filter(|c| c.is_ascii_digit()).collect()
}

/// Remainder of a long decimal digit string modulo `m`, digit by digit, so no
/// value ever overflows.
fn mod_digits(digits: &str, m: u64) -> u64 {
    let mut r: u64 = 0;
    for ch in digits.bytes() {
        r = (r * 10 + u64::from(ch - b'0')) % m;
    }
    r
}

fn all_same_digit(d: &str) -> bool {
    let b = d.as_bytes();
    !b.is_empty() && b.iter().all(|&c| c == b[0])
}

/// Luhn / ISO-IEC 7812-1 mod-10.
pub fn luhn(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() < 2 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut dbl = false;
    for &ch in d.as_bytes().iter().rev() {
        let mut n = u32::from(ch - b'0');
        if dbl {
            n *= 2;
            if n > 9 {
                n -= 9;
            }
        }
        sum += n;
        dbl = !dbl;
    }
    sum % 10 == 0
}

const VERHOEFF_MUL: [[usize; 10]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
];

const VERHOEFF_PERM: [[usize; 10]; 8] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
];

/// Verhoeff, the Aadhaar check digit (UIDAI Circular No. 1 of 2018).
pub fn verhoeff(input: &str) -> bool {
    let d = digits_of(input);
    let mut c = 0usize;
    for (i, &ch) in d.as_bytes().iter().rev().enumerate() {
        c = VERHOEFF_MUL[c][VERHOEFF_PERM[i % 8][usize::from(ch - b'0')]];
    }
    c == 0
}

/// Australian TFN (ATO): weights 1,4,3,7,5,8,6,9,10 over 9 digits, sum mod 11 == 0.
pub fn au_tfn(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 9 {
        return false;
    }
    const W: [u32; 9] = [1, 4, 3, 7, 5, 8, 6, 9, 10];
    let sum: u32 = d
        .as_bytes()
        .iter()
        .enumerate()
        .map(|(i, &c)| u32::from(c - b'0') * W[i])
        .sum();
    sum % 11 == 0
}

/// Australian ABN (ABR): subtract 1 from the first digit, weights 10,1,3..19,
/// sum mod 89 == 0.
pub fn au_abn(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 11 {
        return false;
    }
    const W: [i64; 11] = [10, 1, 3, 5, 7, 9, 11, 13, 15, 17, 19];
    let b = d.as_bytes();
    let mut sum: i64 = (i64::from(b[0] - b'0') - 1) * W[0];
    for i in 1..11 {
        sum += i64::from(b[i] - b'0') * W[i];
    }
    sum % 89 == 0
}

/// Australian Medicare card number (Services Australia).
pub fn au_medicare(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() < 10 {
        return false;
    }
    let b = d.as_bytes();
    if !b"23456".contains(&b[0]) {
        return false;
    }
    const W: [u32; 8] = [1, 3, 7, 9, 1, 3, 7, 9];
    let sum: u32 = (0..8).map(|i| u32::from(b[i] - b'0') * W[i]).sum();
    sum % 10 == u32::from(b[8] - b'0')
}

/// UK NHS number (NHS Data Model and Dictionary): weights 10..2,
/// check = 11 - (sum mod 11); 11 -> 0; 10 is invalid.
pub fn uk_nhs(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 10 {
        return false;
    }
    let b = d.as_bytes();
    let sum: u32 = (0..9).map(|i| u32::from(b[i] - b'0') * (10 - i as u32)).sum();
    let mut check = 11 - (sum % 11);
    if check == 11 {
        check = 0;
    }
    if check == 10 {
        return false;
    }
    check == u32::from(b[9] - b'0')
}

/// Brazil CPF (Receita Federal): two sequential mod-11 check digits.
pub fn br_cpf(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 11 || all_same_digit(&d) {
        return false;
    }
    let b = d.as_bytes();
    let calc = |len: usize| -> u32 {
        let sum: u32 = (0..len)
            .map(|i| u32::from(b[i] - b'0') * (len as u32 + 1 - i as u32))
            .sum();
        let r = (sum * 10) % 11;
        if r == 10 {
            0
        } else {
            r
        }
    };
    calc(9) == u32::from(b[9] - b'0') && calc(10) == u32::from(b[10] - b'0')
}

/// Brazil CNPJ (Receita Federal): two mod-11 check digits with different weight
/// vectors per pass.
pub fn br_cnpj(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 14 || all_same_digit(&d) {
        return false;
    }
    let b = d.as_bytes();
    let calc = |weights: &[u32]| -> u32 {
        let sum: u32 = weights
            .iter()
            .enumerate()
            .map(|(i, &w)| u32::from(b[i] - b'0') * w)
            .sum();
        let r = sum % 11;
        if r < 2 {
            0
        } else {
            11 - r
        }
    };
    calc(&[5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == u32::from(b[12] - b'0')
        && calc(&[6, 5, 4, 3, 2, 9, 8, 7, 6, 5, 4, 3, 2]) == u32::from(b[13] - b'0')
}

/// Japan My Number (MIC Ordinance No. 85 of 2014).
pub fn jp_my_number(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 12 {
        return false;
    }
    let b = d.as_bytes();
    let mut sum: u32 = 0;
    for n in 1..=11u32 {
        let p = u32::from(b[11 - n as usize] - b'0');
        let q = if n <= 6 { n + 1 } else { n - 5 };
        sum += p * q;
    }
    let r = sum % 11;
    let check = if r <= 1 { 0 } else { 11 - r };
    check == u32::from(b[11] - b'0')
}

/// China resident ID (GB 11643-1999): ISO 7064 MOD 11-2 over 17 digits, with a
/// check character that may be X.
pub fn cn_resident_id(input: &str) -> bool {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect();
    let b = s.as_bytes();
    if b.len() != 18 {
        return false;
    }
    if !b[..17].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !(b[17].is_ascii_digit() || b[17] == b'X') {
        return false;
    }
    const W: [u32; 17] = [7, 9, 10, 5, 8, 4, 2, 1, 6, 3, 7, 9, 10, 5, 8, 4, 2];
    let sum: u32 = (0..17).map(|i| u32::from(b[i] - b'0') * W[i]).sum();
    b"10X98765432"[(sum % 11) as usize] == b[17]
}

/// Korea RRN, for numbers issued before 20 Oct 2020.
///
/// ADVISORY ONLY, never a gate: numbers issued from 20 Oct 2020 are randomly
/// assigned and carry no check digit, so rejecting on this would stop detecting
/// every RRN issued since.
pub fn kr_rrn(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 13 {
        return false;
    }
    let b = d.as_bytes();
    const W: [u32; 12] = [2, 3, 4, 5, 6, 7, 8, 9, 2, 3, 4, 5];
    let sum: u32 = (0..12).map(|i| u32::from(b[i] - b'0') * W[i]).sum();
    (11 - (sum % 11)) % 10 == u32::from(b[12] - b'0')
}

/// Singapore NRIC/FIN (ICA): weights 2,7,6,5,4,3,2 and a prefix-dependent
/// check-letter table.
pub fn sg_nric(input: &str) -> bool {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect();
    let b = s.as_bytes();
    if b.len() != 9 {
        return false;
    }
    if !b"STFGM".contains(&b[0]) {
        return false;
    }
    if !b[1..8].iter().all(|c| c.is_ascii_digit()) {
        return false;
    }
    if !b[8].is_ascii_uppercase() {
        return false;
    }
    const W: [u32; 7] = [2, 7, 6, 5, 4, 3, 2];
    let mut sum: u32 = (0..7).map(|i| u32::from(b[1 + i] - b'0') * W[i]).sum();
    let prefix = b[0];
    if prefix == b'T' || prefix == b'G' {
        sum += 4;
    }
    if prefix == b'M' {
        sum += 3;
    }
    let table: &[u8] = match prefix {
        b'S' | b'T' => b"JZIHGFEDCBA",
        b'M' => b"KLJNPQRTUWX",
        _ => b"XWUTRQPNMLK",
    };
    table[(sum % 11) as usize] == b[8]
}

fn cf_odd(c: u8) -> u32 {
    match c {
        b'0' | b'A' => 1,
        b'1' | b'B' => 0,
        b'2' | b'C' => 5,
        b'3' | b'D' => 7,
        b'4' | b'E' => 9,
        b'5' | b'F' => 13,
        b'6' | b'G' => 15,
        b'7' | b'H' => 17,
        b'8' | b'I' => 19,
        b'9' | b'J' => 21,
        b'K' => 2,
        b'L' => 4,
        b'M' => 18,
        b'N' => 20,
        b'O' => 11,
        b'P' => 3,
        b'Q' => 6,
        b'R' => 8,
        b'S' => 12,
        b'T' => 14,
        b'U' => 16,
        b'V' => 10,
        b'W' => 22,
        b'X' => 25,
        b'Y' => 24,
        b'Z' => 23,
        _ => 0,
    }
}

/// Italy codice fiscale (Agenzia delle Entrate): odd and even position
/// character tables, summed mod 26, mapped to a check letter.
pub fn it_codice_fiscale(input: &str) -> bool {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect();
    let b = s.as_bytes();
    if b.len() != 16 {
        return false;
    }
    let shape_ok = b[..6].iter().all(|c| c.is_ascii_uppercase())
        && b[6..8].iter().all(|c| c.is_ascii_digit())
        && b[8].is_ascii_uppercase()
        && b[9..11].iter().all(|c| c.is_ascii_digit())
        && b[11].is_ascii_uppercase()
        && b[12..15].iter().all(|c| c.is_ascii_digit())
        && b[15].is_ascii_uppercase();
    if !shape_ok {
        return false;
    }
    let mut sum: u32 = 0;
    for i in 0..15 {
        let c = b[i];
        sum += if i % 2 == 0 {
            cf_odd(c)
        } else if c.is_ascii_digit() {
            u32::from(c - b'0')
        } else {
            u32::from(c - b'A')
        };
    }
    (b'A' + (sum % 26) as u8) == b[15]
}

/// France NIR (Insee): 97-complement over the 13-digit body, with the Corsican
/// 2A/2B department codes mapped to digits first.
pub fn fr_nir(input: &str) -> bool {
    let s: String = input
        .chars()
        .filter(|c| !c.is_whitespace())
        .flat_map(|c| c.to_uppercase())
        .collect();
    if s.len() != 15 {
        return false;
    }
    let b = s.as_bytes();
    if b[0] != b'1' && b[0] != b'2' {
        return false;
    }
    let dept = &s[5..7];
    let body_ok = b[1..5].iter().all(|c| c.is_ascii_digit())
        && (dept.bytes().all(|c| c.is_ascii_digit()) || dept == "2A" || dept == "2B")
        && b[7..15].iter().all(|c| c.is_ascii_digit());
    if !body_ok {
        return false;
    }
    let normalised = s.replacen("2A", "19", 1).replacen("2B", "18", 1);
    let body = &normalised[..13];
    let key: u64 = normalised[13..].parse().unwrap_or(0);
    97 - mod_digits(body, 97) == key
}

/// Germany Steuer-IdNr (BZSt): ISO 7064 MOD 11,10 over 10 digits.
pub fn de_steuer_id(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 11 {
        return false;
    }
    let b = d.as_bytes();
    if b[0] == b'0' {
        return false;
    }
    let mut product: u32 = 10;
    for i in 0..10 {
        let mut sum = (u32::from(b[i] - b'0') + product) % 10;
        if sum == 0 {
            sum = 10;
        }
        product = (sum * 2) % 11;
    }
    let mut check = 11 - product;
    if check == 10 {
        check = 0;
    }
    check == u32::from(b[10] - b'0')
}

/// Thailand national ID (DOPA): weights 13..2 over 12 digits,
/// check = (11 - sum mod 11) mod 10.
pub fn th_national_id(input: &str) -> bool {
    let d = digits_of(input);
    if d.len() != 13 {
        return false;
    }
    let b = d.as_bytes();
    let sum: u32 = (0..12).map(|i| u32::from(b[i] - b'0') * (13 - i as u32)).sum();
    (11 - (sum % 11)) % 10 == u32::from(b[12] - b'0')
}

/// Canada SIN (Service Canada): Luhn over 9 digits. Advisory -- the algorithm
/// is community-sourced, not authority-published.
pub fn ca_sin(input: &str) -> bool {
    digits_of(input).len() == 9 && luhn(input)
}

/// South Africa ID (SARS PAYE BRS Appendix B 8.3): Luhn over 13 digits.
pub fn za_id(input: &str) -> bool {
    digits_of(input).len() == 13 && luhn(input)
}

/// UAE Emirates ID (ICP): Luhn over 15 digits starting 784. Advisory.
pub fn ae_emirates_id(input: &str) -> bool {
    let d = digits_of(input);
    d.len() == 15 && d.starts_with("784") && luhn(&d)
}

/// Saudi national ID / iqama: Luhn over 10 digits starting 1 or 2. Advisory.
pub fn sa_national_id(input: &str) -> bool {
    let d = digits_of(input);
    d.len() == 10 && (d.starts_with('1') || d.starts_with('2')) && luhn(&d)
}

/// Look a checksum up by the bundle's `checksum` field.
pub fn checksum_fn(name: &str) -> Option<fn(&str) -> bool> {
    Some(match name {
        "luhn" => luhn,
        "verhoeff" => verhoeff,
        "au_tfn" => au_tfn,
        "au_abn" => au_abn,
        "au_medicare" => au_medicare,
        "uk_nhs" => uk_nhs,
        "br_cpf" => br_cpf,
        "br_cnpj" => br_cnpj,
        "jp_my_number" => jp_my_number,
        "cn_resident_id" => cn_resident_id,
        "kr_rrn" => kr_rrn,
        "sg_nric" => sg_nric,
        "it_codice_fiscale" => it_codice_fiscale,
        "fr_nir" => fr_nir,
        "de_steuer_id" => de_steuer_id,
        "th_national_id" => th_national_id,
        "ca_sin" => ca_sin,
        "za_id" => za_id,
        "ae_emirates_id" => ae_emirates_id,
        "sa_national_id" => sa_national_id,
        _ => return None,
    })
}

/// Every checksum the bundle names, for the coverage test.
pub const CHECKSUM_NAMES: &[&str] = &[
    "luhn",
    "verhoeff",
    "au_tfn",
    "au_abn",
    "au_medicare",
    "uk_nhs",
    "br_cpf",
    "br_cnpj",
    "jp_my_number",
    "cn_resident_id",
    "kr_rrn",
    "sg_nric",
    "it_codice_fiscale",
    "fr_nir",
    "de_steuer_id",
    "th_national_id",
    "ca_sin",
    "za_id",
    "ae_emirates_id",
    "sa_national_id",
];

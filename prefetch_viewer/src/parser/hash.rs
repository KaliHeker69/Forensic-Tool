use super::types::PrefetchVersion;

pub fn compute_prefetch_hash(exe_path: &str, version: PrefetchVersion) -> u32 {
    let path_upper = exe_path.to_uppercase();
    let chars: Vec<u16> = path_upper.encode_utf16().collect();

    match version {
        PrefetchVersion::V17 => compute_hash_xp(&chars),
        PrefetchVersion::V23 => {
            // Vista uses simple hash, Win7 uses 2008 hash
            // Since we can't distinguish, try the Vista hash first
            compute_hash_vista(&chars)
        }
        _ => compute_hash_2008(&chars),
    }
}

/// XP-era hash (version 17)
fn compute_hash_xp(chars: &[u16]) -> u32 {
    let mut hash: u32 = 0;
    for &ch in chars {
        hash = hash.wrapping_mul(37).wrapping_add(ch as u32);
    }
    hash = hash.wrapping_mul(314159269);
    if hash > 0x8000_0000 {
        hash = 0u32.wrapping_sub(hash);
    }
    hash % 1_000_000_007
}

/// Vista hash (version 23)
fn compute_hash_vista(chars: &[u16]) -> u32 {
    let mut hash: u32 = 314159;
    for &ch in chars {
        hash = hash.wrapping_mul(37).wrapping_add(ch as u32);
    }
    hash
}

/// 2008/Win7+ hash (versions 23-Win7, 26, 30, 31)
fn compute_hash_2008(chars: &[u16]) -> u32 {
    let mut hash: u32 = 314159;
    let len = chars.len();
    let mut i = 0;

    // Process 8 characters at a time
    while i + 8 <= len {
        let mut val: u32 = (chars[i + 1] as u32).wrapping_mul(37);
        val = val.wrapping_add(chars[i + 2] as u32);
        val = val.wrapping_mul(37);
        val = val.wrapping_add(chars[i + 3] as u32);
        val = val.wrapping_mul(37);
        val = val.wrapping_add(chars[i + 4] as u32);
        val = val.wrapping_mul(37);
        val = val.wrapping_add(chars[i + 5] as u32);
        val = val.wrapping_mul(37);
        val = val.wrapping_add(chars[i + 6] as u32);
        val = val.wrapping_mul(37);
        val = val.wrapping_add((chars[i] as u32).wrapping_mul(442596621));
        val = val.wrapping_add(chars[i + 7] as u32);
        hash = val.wrapping_sub(hash.wrapping_mul(803794207));
        i += 8;
    }

    // Process remaining characters
    while i < len {
        hash = hash.wrapping_mul(37).wrapping_add(chars[i] as u32);
        i += 1;
    }

    hash
}

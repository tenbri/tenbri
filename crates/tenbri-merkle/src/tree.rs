//! The RFC 6962 Merkle tree (RFC 9162, section 2.1) over leaf hashes that are already hashed:
//! Tenbri's entry hashes are the RFC 6962 leaf hash `SHA-256(0x00 || line)`, so they are used as
//! the leaves unchanged. Leaf `i` (from 0) is entry `seq = i + 1`.

use sha2::{Digest, Sha256};

/// A 32-byte SHA-256 hash.
pub type Hash = [u8; 32];

/// An interior node: `SHA-256(0x01 || left || right)`.
pub fn node(left: &Hash, right: &Hash) -> Hash {
    let mut h = Sha256::new();
    h.update([1u8]);
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// The largest power of two smaller than `n` (n > 1).
fn split(n: usize) -> usize {
    1 << (usize::BITS - 1 - (n - 1).leading_zeros())
}

/// The Merkle tree hash of `leaves`; the empty tree's is SHA-256 of nothing.
// ponytail: recomputes the whole tree, O(n) per call; keep a compact range (the right edge's
// subtree roots) in the writer if checkpointing millions of entries gets slow.
pub fn root(leaves: &[Hash]) -> Hash {
    match leaves.len() {
        0 => Sha256::digest([]).into(),
        1 => leaves[0],
        n => {
            let k = split(n);
            node(&root(&leaves[..k]), &root(&leaves[k..]))
        }
    }
}

/// The audit path of leaf `index` in the tree of `leaves`, leaf side first. `None` if `index` is
/// not in the tree.
pub fn inclusion_proof(leaves: &[Hash], index: u64) -> Option<Vec<Hash>> {
    fn path(index: usize, leaves: &[Hash], out: &mut Vec<Hash>) {
        if leaves.len() > 1 {
            let k = split(leaves.len());
            if index < k {
                path(index, &leaves[..k], out);
                out.push(root(&leaves[k..]));
            } else {
                path(index - k, &leaves[k..], out);
                out.push(root(&leaves[..k]));
            }
        }
    }
    let index = usize::try_from(index).ok().filter(|&i| i < leaves.len())?;
    let mut out = vec![];
    path(index, leaves, &mut out);
    Some(out)
}

/// The proof that the tree of the first `size` leaves is a prefix of the tree of all `leaves`.
/// `None` if `size` is larger than the tree.
pub fn consistency_proof(leaves: &[Hash], size: u64) -> Option<Vec<Hash>> {
    fn sub(m: usize, leaves: &[Hash], whole: bool, out: &mut Vec<Hash>) {
        let n = leaves.len();
        if m == n {
            if !whole {
                out.push(root(leaves));
            }
            return;
        }
        let k = split(n);
        if m <= k {
            sub(m, &leaves[..k], whole, out);
            out.push(root(&leaves[k..]));
        } else {
            sub(m - k, &leaves[k..], false, out);
            out.push(root(&leaves[..k]));
        }
    }
    let m = usize::try_from(size).ok().filter(|&m| m <= leaves.len())?;
    let mut out = vec![];
    if m > 0 {
        sub(m, leaves, true, &mut out);
    }
    Some(out)
}

/// Whether `proof` shows `leaf` at `index` in the tree of `size` leaves with `root`
/// (RFC 9162, section 2.1.3.2).
pub fn verify_inclusion(index: u64, size: u64, leaf: &Hash, proof: &[Hash], root: &Hash) -> bool {
    if index >= size {
        return false;
    }
    let (mut f, mut s, mut r) = (index, size - 1, *leaf);
    for p in proof {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            r = node(p, &r);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            r = node(&r, p);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && r == *root
}

/// Whether `proof` shows the tree of `old_size` leaves with `old_root` is a prefix of the tree of
/// `new_size` leaves with `new_root` (RFC 9162, section 2.1.4.2). Equal sizes need an empty proof
/// and equal roots; every tree extends the empty one.
pub fn verify_consistency(
    old_size: u64,
    new_size: u64,
    old_root: &Hash,
    new_root: &Hash,
    proof: &[Hash],
) -> bool {
    if old_size > new_size {
        return false;
    }
    if old_size == new_size {
        return proof.is_empty() && old_root == new_root;
    }
    if old_size == 0 {
        return proof.is_empty();
    }
    if proof.is_empty() {
        return false;
    }
    let mut path = proof;
    let mut seed = *old_root;
    if !old_size.is_power_of_two() {
        seed = proof[0];
        path = &proof[1..];
    }
    let (mut f, mut s) = (old_size - 1, new_size - 1);
    while f & 1 == 1 {
        f >>= 1;
        s >>= 1;
    }
    let (mut fr, mut sr) = (seed, seed);
    for c in path {
        if s == 0 {
            return false;
        }
        if f & 1 == 1 || f == s {
            fr = node(c, &fr);
            sr = node(c, &sr);
            while f & 1 == 0 && f != 0 {
                f >>= 1;
                s >>= 1;
            }
        } else {
            sr = node(&sr, c);
        }
        f >>= 1;
        s >>= 1;
    }
    s == 0 && fr == *old_root && sr == *new_root
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(h: &Hash) -> String {
        tenbri_core::encoding::hex(h)
    }

    /// RFC 6962's reference tree (certificate-transparency's merkle_tree_test): eight leaves and
    /// the root at every size.
    #[test]
    fn rfc6962_reference_roots() {
        let data: [&[u8]; 8] = [
            b"",
            b"\x00",
            b"\x10",
            b"\x20\x21",
            b"\x30\x31",
            b"\x40\x41\x42\x43",
            b"\x50\x51\x52\x53\x54\x55\x56\x57",
            b"\x60\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f",
        ];
        let leaves: Vec<Hash> = data
            .iter()
            .map(|d| {
                let h = tenbri_core::sign::entry_hash(d);
                tenbri_core::encoding::prefixed::<32>(&h, "sha256:").unwrap()
            })
            .collect();
        let roots = [
            "6e340b9cffb37a989ca544e6bb780a2c78901d3fb33738768511a30617afa01d",
            "fac54203e7cc696cf0dfcb42c92a1d9dbaf70ad9e621f4bd8d98662f00e3c125",
            "aeb6bcfe274b70a14fb067a5e5578264db0fa9b51af5e0ba159158f329e06e77",
            "d37ee418976dd95753c1c73862b9398fa2a2cf9b4ff0fdfe8b30cd95209614b7",
            "4e3bbb1f7b478dcfe71fb631631519a3bca12c9aefca1612bfce4c13a86264d4",
            "76e67dadbcdf1e10e1b74ddc608abd2f98dfb16fbce75277b5232a127f2087ef",
            "ddb89be403809e325750d3d263cd78929c2942b7942a34b77e122c9594a74c8c",
            "5dc9da79a70659a9ad559cb701ded9a2ab9d823aad2f4960cfe370eff4604328",
        ];
        for (n, want) in roots.iter().enumerate() {
            assert_eq!(hex(&root(&leaves[..=n])), *want, "size {}", n + 1);
        }
        assert_eq!(
            hex(&root(&[])),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn every_proof_up_to_33_leaves_verifies_and_tampered_ones_do_not() {
        let leaves: Vec<Hash> = (0u8..33).map(|i| [i; 32]).collect();
        for n in 1..=leaves.len() {
            let t = &leaves[..n];
            let r = root(t);
            for i in 0..n as u64 {
                let p = inclusion_proof(t, i).unwrap();
                assert!(verify_inclusion(i, n as u64, &t[i as usize], &p, &r));
                if let Some(mut q) = p.first().map(|_| p.clone()) {
                    q[0][0] ^= 1;
                    assert!(!verify_inclusion(i, n as u64, &t[i as usize], &q, &r));
                }
                assert!(!verify_inclusion(i ^ 1, n as u64, &t[i as usize], &p, &r));
            }
            assert_eq!(inclusion_proof(t, n as u64), None);
            for m in 0..=n as u64 {
                let p = consistency_proof(t, m).unwrap();
                let old = root(&t[..m as usize]);
                assert!(verify_consistency(m, n as u64, &old, &r, &p), "{m} {n}");
                if m > 0 && (m as usize) < n {
                    assert!(!verify_consistency(m, n as u64, &r, &r, &p), "{m} {n}");
                    let mut q = p.clone();
                    q[0][0] ^= 1;
                    assert!(!verify_consistency(m, n as u64, &old, &r, &q), "{m} {n}");
                }
            }
            assert_eq!(consistency_proof(t, n as u64 + 1), None);
        }
    }
}

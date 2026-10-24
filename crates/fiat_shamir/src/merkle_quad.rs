//! Experimental quaternary authentication over the existing flat allocation.
use super::*;

fn arity(width: usize) -> usize {
    if width >= 4 { 4 } else { 2 }
}
fn hash_children(children: &[Hash]) -> Hash {
    let bytes: Vec<_> = children.iter().flat_map(|h| h.iter().copied()).collect();
    primitives::protocol_hash::hash(&bytes)
}

pub(super) fn prune(
    tree: &[Hash],
    n: usize,
    positions: &[usize],
    row: impl Fn(usize) -> Vec<F64>,
) -> PrunedMerklePaths {
    assert!(n.is_power_of_two() && n > 0);
    assert_eq!(tree.len(), 2 * n - 1);
    let sorted = sorted_unique(positions);
    assert!(sorted.iter().all(|&p| p < n));
    let mut active = sorted.clone();
    let mut siblings = Vec::new();
    let (mut start, mut width) = (0, n);
    while width > 1 {
        let a = arity(width);
        let mut next = Vec::new();
        let mut i = 0;
        while i < active.len() {
            let parent = active[i] / a;
            let begin = i;
            while i < active.len() && active[i] / a == parent {
                i += 1;
            }
            for child in parent * a..(parent + 1) * a {
                if active[begin..i].binary_search(&child).is_err() {
                    siblings.push(tree[start + child]);
                }
            }
            next.push(parent);
        }
        active = next;
        start += if a == 4 { width + width / 2 } else { width };
        width /= a;
    }
    PrunedMerklePaths {
        leaf_data: sorted.iter().map(|&q| row(q)).collect(),
        sibling_hashes: siblings,
    }
}

pub(super) fn open(
    proof: &PrunedMerklePaths,
    root: &Hash,
    n: usize,
    queries: &[usize],
    row_words: usize,
    leaf_words: usize,
) -> Option<Vec<RawMerklePath>> {
    if n == 0 || !n.is_power_of_two() || queries.is_empty() {
        return None;
    }
    let (sorted, leaves) = proof.leaf_hashes(queries, row_words, leaf_words)?;
    if sorted.last().is_some_and(|&p| p >= n) {
        return None;
    }
    let mut supplied = proof.sibling_hashes.iter();
    let mut nodes: Vec<_> = sorted.iter().copied().zip(leaves).collect();
    let mut known = Vec::new();
    let mut width = n;
    while width > 1 {
        let a = arity(width);
        let mut level = Vec::new();
        let mut parents = Vec::new();
        let mut i = 0;
        while i < nodes.len() {
            let parent = nodes[i].0 / a;
            let mut children = Vec::new();
            for child in parent * a..(parent + 1) * a {
                let digest = if nodes.get(i).is_some_and(|n| n.0 == child) {
                    let digest = nodes[i].1;
                    i += 1;
                    digest
                } else {
                    *supplied.next()?
                };
                children.push(digest);
                level.push((child, digest));
            }
            parents.push((parent, hash_children(&children)));
        }
        known.push((a, level));
        nodes = parents;
        width /= a;
    }
    if supplied.next().is_some() || nodes[0].1 != *root {
        return None;
    }
    let paths: Vec<Vec<Hash>> = sorted
        .iter()
        .map(|&q| {
            let mut q = q;
            let mut path = Vec::new();
            for (a, level) in &known {
                for sibling in q / a * a..(q / a + 1) * a {
                    if sibling != q {
                        let at = level.binary_search_by_key(&sibling, |&(j, _)| j).ok()?;
                        path.push(level[at].1);
                    }
                }
                q /= a;
            }
            Some(path)
        })
        .collect::<Option<_>>()?;
    queries
        .iter()
        .map(|q| {
            let slot = sorted.binary_search(q).ok()?;
            Some(RawMerklePath {
                leaf_index: *q,
                leaf_data: leaf_image(&proof.leaf_data[slot], leaf_words),
                path: paths[slot].clone(),
            })
        })
        .collect()
}

pub(super) fn root(path: &RawMerklePath, mut index: usize) -> Hash {
    let mut acc = hash_words(&path.leaf_data);
    let mut cursor = 0;
    while cursor < path.path.len() {
        let a = if path.path.len() - cursor >= 3 { 4 } else { 2 };
        let slot = index % a;
        let mut children = Vec::new();
        for child in 0..a {
            children.push(if child == slot {
                acc
            } else {
                let h = path.path[cursor];
                cursor += 1;
                h
            });
        }
        acc = hash_children(&children);
        index /= a;
    }
    acc
}

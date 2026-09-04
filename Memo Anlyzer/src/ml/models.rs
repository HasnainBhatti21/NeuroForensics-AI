//! Isolation Forest implementation (built from scratch, deterministic).
//!
//! Spec §38/§53: the model is local and offline, versioned, and only ever
//! trained on features extracted from the currently open case. It never
//! receives data from the investigator's system.

use serde::Serialize;

/// Versioned model identifier reported in findings (spec §39).
pub const MODEL_ID: &str = "neuro-cpu-gpu-anomaly-v1";

/// Deterministic xorshift64* RNG so repeated analysis runs are identical.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed)
    }
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn next_range(&mut self, exclusive_max: usize) -> usize {
        (self.next_u64() % exclusive_max as u64) as usize
    }
}

#[derive(Clone, Debug, Serialize)]
enum TreeNode {
    Split { feature: usize, value: f64, left: Box<TreeNode>, right: Box<TreeNode> },
    Leaf { size: usize },
}

#[derive(Clone, Debug, Serialize)]
pub struct IsolationForest {
    pub model_id: &'static str,
    pub n_trees: usize,
    pub sample_size: usize,
    trees: Vec<TreeNode>,
}

impl IsolationForest {
    /// Fit on the given samples (each row = one feature vector).
    pub fn fit(samples: &[Vec<f64>], n_trees: usize, sample_size: usize, seed: u64) -> Self {
        let mut rng = Rng::new(seed);
        let mut trees = Vec::with_capacity(n_trees);
        let depth_limit = (sample_size.max(2) as f64).log2().ceil() as usize + 1;
        for _ in 0..n_trees {
            let mut subset: Vec<&Vec<f64>> = if samples.len() <= sample_size {
                samples.iter().collect()
            } else {
                let mut picked = Vec::with_capacity(sample_size);
                let mut seen = std::collections::HashSet::new();
                while picked.len() < sample_size {
                    let i = rng.next_range(samples.len());
                    if seen.insert(i) {
                        picked.push(&samples[i]);
                    }
                }
                picked
            };
            trees.push(build_tree(&mut subset, 0, depth_limit, &mut rng));
        }
        Self { model_id: MODEL_ID, n_trees, sample_size, trees }
    }

    /// Anomaly score in (0, 1); values close to 1 are more anomalous.
    pub fn score(&self, point: &[f64]) -> f64 {
        let sample_n = self.sample_size.max(2);
        let cn = average_path_length(sample_n);
        let mean_path: f64 =
            self.trees.iter().map(|t| path_length(point, t, 0)).sum::<f64>() / self.trees.len() as f64;
        2f64.powf(-mean_path / cn)
    }
}

fn build_tree(subset: &mut [&Vec<f64>], depth: usize, depth_limit: usize, rng: &mut Rng) -> TreeNode {
    if subset.len() <= 1 || depth >= depth_limit {
        return TreeNode::Leaf { size: subset.len() };
    }
    let n_features = subset[0].len();
    // Try a few random features to find one with variance in this subset.
    for _ in 0..4 {
        let feature = rng.next_range(n_features);
        let mut min = f64::INFINITY;
        let mut max = f64::NEG_INFINITY;
        for row in subset.iter() {
            min = min.min(row[feature]);
            max = max.max(row[feature]);
        }
        if max > min {
            // Deterministic split within observed range.
            let frac = rng.next_u64() as f64 / u64::MAX as f64;
            let value = min + (max - min) * frac;
            let (mut left_refs, mut right_refs): (Vec<&Vec<f64>>, Vec<&Vec<f64>>) = (Vec::new(), Vec::new());
            for row in subset.iter() {
                if row[feature] < value {
                    left_refs.push(row);
                } else {
                    right_refs.push(row);
                }
            }
            if left_refs.is_empty() || right_refs.is_empty() {
                continue;
            }
            let left = build_tree(&mut left_refs, depth + 1, depth_limit, rng);
            let right = build_tree(&mut right_refs, depth + 1, depth_limit, rng);
            return TreeNode::Split { feature, value, left: Box::new(left), right: Box::new(right) };
        }
    }
    TreeNode::Leaf { size: subset.len() }
}

fn path_length(point: &[f64], node: &TreeNode, depth: usize) -> f64 {
    match node {
        TreeNode::Leaf { size } => depth as f64 + average_path_length(*size),
        TreeNode::Split { feature, value, left, right } => {
            let next = if point[*feature] < *value { left } else { right };
            path_length(point, next, depth + 1)
        }
    }
}

/// c(n): average path length of an unsuccessful BST search.
fn average_path_length(n: usize) -> f64 {
    match n {
        0 => 0.0,
        1 => 0.0,
        _ => {
            let nf = n as f64;
            2.0 * (nf.ln() + std::f64::consts::EULER_GAMMA) - 2.0 * (nf - 1.0) / nf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outlier_scores_higher_than_cluster() {
        let mut samples: Vec<Vec<f64>> = (0..64)
            .map(|i| vec![10.0 + (i % 5) as f64 * 0.1, 1.0])
            .collect();
        samples.push(vec![95.0, 12.0]); // injected outlier
        let forest = IsolationForest::fit(&samples, 50, 32, 0xA5A5);
        let outlier = forest.score(&[95.0, 12.0]);
        let normal = forest.score(&[10.2, 1.0]);
        assert!(outlier > normal, "outlier {outlier} should exceed normal {normal}");
        assert!(outlier <= 1.0 && normal >= 0.0);
    }

    #[test]
    fn deterministic_across_runs() {
        let samples: Vec<Vec<f64>> = (0..40).map(|i| vec![i as f64, (i * 2) as f64]).collect();
        let a = IsolationForest::fit(&samples, 25, 16, 42);
        let b = IsolationForest::fit(&samples, 25, 16, 42);
        assert_eq!(a.score(&[7.0, 14.0]), b.score(&[7.0, 14.0]));
    }
}

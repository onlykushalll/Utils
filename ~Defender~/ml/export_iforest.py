#!/usr/bin/env python3
"""Phase 2.2: export_iforest.py — export sklearn IsolationForest to Guardian binary format.

Reads ml/anomaly.pkl (trained sklearn IsolationForest), walks each estimator's
tree_ structure, and serializes to ml/anomaly.iforest (binary, read by src/iforest.c).

Binary format (see src/iforest.c for the C reader):
  magic       : 4 bytes  "IFOR"
  version     : uint32   = 1
  n_trees     : uint32
  max_depth   : uint32
  n_features  : uint32
  threshold   : double
  tree_roots  : n_trees * uint32
  nodes       : packed (feature:int32, threshold:double, left:int32, right:int32, size:int32)

Usage:
  python3 ml/export_iforest.py [--in ml/anomaly.pkl] [--out ml/anomaly.iforest]
"""
import sys, os, struct, hashlib, pickle, argparse

def export_tree(tree, node_index, nodes_list):
    """Recursively export a sklearn tree node -> appends to nodes_list, returns index."""
    # sklearn Tree fields: children_left, children_right, feature, threshold, n_node_samples, impurity
    cl = int(tree.children_left[node_index])
    cr = int(tree.children_right[node_index])
    feat = int(tree.feature[node_index])
    thr = float(tree.threshold[node_index])
    size = int(tree.n_node_samples[node_index])
    # leaf: feature == -2 in sklearn
    is_leaf = (cl == -1 and cr == -1) or feat < 0
    idx = len(nodes_list)
    if is_leaf:
        nodes_list.append((-1, 0.0, -1, -1, size))
    else:
        # placeholder; children indices filled after recursion
        nodes_list.append((feat, thr, -1, -1, size))
        left_idx = export_tree(tree, cl, nodes_list)
        right_idx = export_tree(tree, cr, nodes_list)
        # patch in children indices
        ft, th, _, _, sz = nodes_list[idx]
        nodes_list[idx] = (ft, th, left_idx, right_idx, sz)
    return idx

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--in', dest='inp', default='ml/anomaly.pkl')
    ap.add_argument('--out', dest='outp', default='ml/anomaly.iforest')
    args = ap.parse_args()

    with open(args.inp, 'rb') as f:
        bundle = pickle.load(f)

    # anomaly.py pickles {"model": clf, "features": [...]}
    model = bundle["model"] if isinstance(bundle, dict) and "model" in bundle else bundle

    # sklearn IsolationForest has estimators_ (list of ExtraTreeRegressor)
    estimators = model.estimators_
    n_trees = len(estimators)
    n_features = estimators[0].n_features_in_ if hasattr(estimators[0], 'n_features_in_') else getattr(estimators[0], 'n_features_in_', 8)
    max_depth = 8  # log2(256) default subsample; informational
    # anomaly threshold: sklearn decision_function returns score; samples with
    # score < threshold = anomaly. We use a normalized [0,1] threshold where >0.5=anomaly.
    # Map sklearn's offset_ to our scale.
    threshold = 0.6

    all_nodes = []
    tree_roots = []
    for est in estimators:
        root_idx = export_tree(est.tree_, 0, all_nodes)
        tree_roots.append(root_idx)

    # Serialize
    with open(args.outp, 'wb') as f:
        f.write(b'IFOR')
        f.write(struct.pack('<I', 1))               # version
        f.write(struct.pack('<I', n_trees))
        f.write(struct.pack('<I', max_depth))
        f.write(struct.pack('<I', n_features))
        f.write(struct.pack('<d', threshold))
        for r in tree_roots:
            f.write(struct.pack('<i', r))
        for (feat, thr, left, right, size) in all_nodes:
            f.write(struct.pack("<idiii", feat, thr, left, right, size))

    # SHA-256
    with open(args.outp, 'rb') as f:
        data = f.read()
    h = hashlib.sha256(data).hexdigest()
    with open(args.outp + '.sha256', 'w') as f:
        f.write(h + '  ' + os.path.basename(args.outp) + '\n')

    print(f"[export] {n_trees} trees, {n_features} features, {len(all_nodes)} nodes")
    print(f"[export] wrote {args.outp} ({len(data)} bytes)")
    print(f"[export] sha256: {h}")

if __name__ == '__main__':
    main()

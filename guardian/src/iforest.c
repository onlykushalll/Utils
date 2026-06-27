/* iforest.c — Phase 2.2: Isolation Forest inference engine in pure C.
 *
 * Replaces the Python subprocess approach (anomaly_engine.c fork+exec python3
 * per PID, ~300ms each, capped at 50 PIDs/cycle). Native C inference is ~0.1ms
 * per PID, eliminating the cap entirely.
 *
 * Binary format (ml/anomaly.iforest):
 *   magic       : 4 bytes  "IFOR"
 *   version     : uint32   = 1
 *   n_trees     : uint32
 *   max_depth   : uint32
 *   n_features  : uint32
 *   threshold   : double   (anomaly score threshold, e.g. 0.6)
 *   tree_roots  : n_trees * uint32  (index into nodes array)
 *   nodes       : packed array of:
 *       feature   : int32   (-1 = leaf)
 *       threshold : double
 *       left      : int32   (-1 = null)
 *       right     : int32   (-1 = null)
 *       size      : int32   (training points in leaf)
 *
 * Algorithm: average path length across trees, normalized to [0,1] anomaly score.
 * 0.5 = normal, >0.5 = anomaly. See DEEP_RESEARCH.md §12.2.
 */
#include "guardian.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdint.h>

#define IFOR_MAGIC "IFOR"
#define IFOR_VERSION 1

/* BUG 3 fix: __attribute__((packed)) so the C layout matches the Python
 * struct.pack('<idiii') format (24 bytes, no padding). Without packed, the
 * double forces 4 bytes of padding -> 28 bytes -> garbled reads. */
typedef struct __attribute__((packed)) {
    int32_t feature;
    double  threshold;
    int32_t left;
    int32_t right;
    int32_t size;
} itree_node_t;

struct g_iforest {
    itree_node_t *nodes;
    int32_t *tree_roots;
    uint32_t n_trees;
    uint32_t max_depth;
    uint32_t n_features;
    size_t   n_nodes;   /* BUG 9: bounds check for tree-walk safety */
    double threshold;
};

/* Euler-Mascheroni constant for path-length correction */
#define GAMMA 0.5772156649015328606

static double avg_path_len_unbiased(int n) {
    /* c(n) = 2*H(n-1) - 2*(n-1)/n, where H(k) = ln(k) + GAMMA */
    if (n <= 1) return 0.0;
    return 2.0 * (log((double)(n - 1)) + GAMMA) - 2.0 * (double)(n - 1) / (double)n;
}

/* Score a single sample: returns anomaly score in [0,1], >0.5 = anomaly */
double g_iforest_score(const g_iforest_t *f, const double *features) {
    if (!f || !features || f->n_trees == 0) return 0.0;
    double total_path = 0.0;
    for (uint32_t t = 0; t < f->n_trees; t++) {
        int32_t node = f->tree_roots[t];
        if (node < 0) continue;
        uint32_t depth = 0;
        /* walk the tree until a leaf (feature == -1) */
        while (node >= 0 && (size_t)node < f->n_nodes &&
               f->nodes[node].feature != -1 && depth < f->max_depth + 16) {
            int feat = f->nodes[node].feature;
            if (feat < 0 || (uint32_t)feat >= f->n_features) break;
            if (features[feat] < f->nodes[node].threshold) {
                node = f->nodes[node].left;
            } else {
                node = f->nodes[node].right;
            }
            depth++;
        }
        /* leaf correction */
        int leaf_size = (node >= 0) ? f->nodes[node].size : 1;
        total_path += (double)depth + avg_path_len_unbiased(leaf_size);
    }
    double avg = total_path / (double)f->n_trees;
    /* normalize: s = 2^(-avg / c(256)) */
    double c256 = avg_path_len_unbiased(256);
    double s = pow(2.0, -avg / (c256 > 0 ? c256 : 1.0));
    return s;
}

g_iforest_t *g_iforest_load(const char *path) {
    if (!path) return NULL;
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;

    char magic[4];
    if (fread(magic, 1, 4, f) != 4 || memcmp(magic, IFOR_MAGIC, 4) != 0) {
        fclose(f); return NULL;
    }
    uint32_t version, n_trees, max_depth, n_features;
    double threshold;
    if (fread(&version, 4, 1, f) != 1 || version != IFOR_VERSION) { fclose(f); return NULL; }
    if (fread(&n_trees, 4, 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&max_depth, 4, 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&n_features, 4, 1, f) != 1) { fclose(f); return NULL; }
    if (fread(&threshold, 8, 1, f) != 1) { fclose(f); return NULL; }
    if (n_trees == 0 || n_trees > 10000 || n_features == 0 || n_features > 256) {
        fclose(f); return NULL;
    }

    g_iforest_t *ifo = calloc(1, sizeof(*ifo));
    if (!ifo) { fclose(f); return NULL; }
    ifo->n_trees = n_trees;
    ifo->max_depth = max_depth;
    ifo->n_features = n_features;
    ifo->threshold = threshold;

    ifo->tree_roots = malloc(n_trees * sizeof(int32_t));
    if (!ifo->tree_roots) { free(ifo); fclose(f); return NULL; }
    if (fread(ifo->tree_roots, 4, n_trees, f) != n_trees) {
        free(ifo->tree_roots); free(ifo); fclose(f); return NULL;
    }

    /* read nodes until EOF */
    long node_start = ftell(f);
    fseek(f, 0, SEEK_END);
    long node_end = ftell(f);
    fseek(f, node_start, SEEK_SET);
    size_t node_sz = sizeof(itree_node_t);
    size_t n_nodes = (node_end - node_start) / node_sz;
    if (n_nodes == 0 || n_nodes > 1000000) {
        free(ifo->tree_roots); free(ifo); fclose(f); return NULL;
    }
    ifo->nodes = malloc(n_nodes * node_sz);
    if (!ifo->nodes) {
        free(ifo->tree_roots); free(ifo); fclose(f); return NULL;
    }
    if (fread(ifo->nodes, node_sz, n_nodes, f) != n_nodes) {
        free(ifo->nodes); free(ifo->tree_roots); free(ifo); fclose(f); return NULL;
    }
    ifo->n_nodes = n_nodes;  /* BUG 9: store for bounds checking */
    fclose(f);
    printf("[iforest] loaded: %u trees, %u features, %zu nodes, threshold=%.3f\n",
           n_trees, n_features, n_nodes, threshold);
    return ifo;
}

void g_iforest_free(g_iforest_t *ifo) {
    if (!ifo) return;
    free(ifo->nodes);
    free(ifo->tree_roots);
    free(ifo);
}

uint32_t g_iforest_n_features(const g_iforest_t *ifo) {
    return ifo ? ifo->n_features : 0;
}

double g_iforest_threshold(const g_iforest_t *ifo) {
    return ifo ? ifo->threshold : 0.6;
}

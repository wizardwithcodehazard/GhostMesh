#!/usr/bin/env python3
# train_export.py (improved)
# Run on PC: python train_export.py

import os
import json
import random
import pickle
import math
import argparse
from collections import Counter

import numpy as np

# ---------- Config / CLI ----------
parser = argparse.ArgumentParser(description="Train small intent classifier and export model weights (pure JSON).")
parser.add_argument("--intents", type=str, default="intents.json", help="Path to intents.json")
parser.add_argument("--out", type=str, default="model", help="Output directory")
parser.add_argument("--hidden", type=int, default=32, help="Hidden layer size")
parser.add_argument("--epochs", type=int, default=500, help="Number of epochs")
parser.add_argument("--batch", type=int, default=8, help="Batch size (mini-batch SGD)")
parser.add_argument("--lr", type=float, default=0.1, help="Initial learning rate")
parser.add_argument("--decay", type=float, default=0.0, help="LR decay (simple 1/(1+decay*epoch))")
parser.add_argument("--seed", type=int, default=42, help="Random seed (reproducibility)")
parser.add_argument("--val-split", type=float, default=0.15, help="Validation split fraction")
parser.add_argument("--early-stop-patience", type=int, default=40, help="Early stopping patience on val loss")
parser.add_argument("--no-augment", action="store_true", help="Disable simple pattern augmentation")
args = parser.parse_args()

INTENTS_FILE = args.intents
OUT_DIR = args.out
os.makedirs(OUT_DIR, exist_ok=True)

HIDDEN_SIZE = args.hidden
EPOCHS = args.epochs
BATCH_SIZE = args.batch
LR = args.lr
DECAY = args.decay
SEED = args.seed
VAL_SPLIT = args.val_split
PATIENCE = args.early_stop_patience
AUGMENT = not args.no_augment

random.seed(SEED)
np.random.seed(SEED)

# ---------- Optional NLTK (safe) ----------
USE_NLTK = False
try:
    import nltk
    from nltk.stem import WordNetLemmatizer
    # check for resources — don't attempt network download automatically
    try:
        nltk.data.find("tokenizers/punkt")
        nltk.data.find("corpora/wordnet")
        USE_NLTK = True
    except LookupError:
        # resources missing -> do not fail, use fallback
        USE_NLTK = False
except Exception:
    USE_NLTK = False

if USE_NLTK:
    lemmatizer = WordNetLemmatizer()
else:
    # simple fallback lemmatizer (lightweight)
    class SimpleLemmatizer:
        def lemmatize(self, w):
            # basic rules
            if w.endswith("ing") and len(w) > 4:
                return w[:-3]
            if w.endswith("ed") and len(w) > 3:
                return w[:-2]
            if w.endswith("s") and len(w) > 2:
                return w[:-1]
            return w
    lemmatizer = SimpleLemmatizer()

# ---------- Tokenizer ----------
import re
def simple_tokenize(text):
    text = re.sub(r"[^a-z0-9\s']", " ", text.lower())
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    return text.split()

def collapse_repeats(word):
    # hiii -> hi, hellooo -> helo (keeps single occurrence)
    return re.sub(r'(.)\1+', r'\1', word)

def tokenize(text):
    text = text.strip()
    if USE_NLTK:
        try:
            tokens = nltk.word_tokenize(text)
            tokens = [t.lower() for t in tokens if t.strip()]
            return tokens
        except Exception:
            pass
    return simple_tokenize(text)

# ---------- Load intents & build dataset ----------
with open(INTENTS_FILE, "r", encoding="utf-8") as f:
    intents = json.load(f)

patterns = []
labels = []
all_words = []

for intent in intents.get("intents", []):
    tag = intent.get("tag")
    for pat in intent.get("patterns", []):
        pats_to_add = [pat]
        if AUGMENT:
            lower = pat.lower()
            # collapse repeated letters in words
            tokens = tokenize(pat)
            collapsed = " ".join(collapse_repeats(t) for t in tokens)
            stripped = re.sub(r"[^\w\s]", " ", pat)  # remove punctuation variant
            if lower not in pats_to_add:
                pats_to_add.append(lower)
            if collapsed not in pats_to_add:
                pats_to_add.append(collapsed)
            if stripped not in pats_to_add:
                pats_to_add.append(stripped)
        for p in pats_to_add:
            toks = tokenize(p)
            if not toks:
                continue
            patterns.append(toks)
            labels.append(tag)
            all_words.extend([lemmatizer.lemmatize(t.lower()) for t in toks])

# Build vocabulary and classes
ignore_tokens = set(["?", "!", ".", ",", "'"])
vocab = sorted(set(w for w in all_words if w not in ignore_tokens))
classes = sorted(set(labels))

# Save vocab & classes for inference usage
pickle.dump(vocab, open(os.path.join(OUT_DIR, "words.pkl"), "wb"))
pickle.dump(classes, open(os.path.join(OUT_DIR, "classes.pkl"), "wb"))

# Map words -> index
word2idx = {w: i for i, w in enumerate(vocab)}
label2idx = {c: i for i, c in enumerate(classes)}

# Build BOW dataset
def bow_from_tokens(tokens):
    tokens = [lemmatizer.lemmatize(t.lower()) for t in tokens]
    b = [0.0] * len(vocab)
    s = set(tokens)
    for w in s:
        if w in word2idx:
            b[word2idx[w]] = 1.0
    return b

X = [bow_from_tokens(toks) for toks in patterns]
y = []
for lab in labels:
    vec = [0.0] * len(classes)
    vec[label2idx[lab]] = 1.0
    y.append(vec)

X = np.array(X, dtype=np.float32)
y = np.array(y, dtype=np.float32)

# Shuffle + train/val split (deterministic)
indices = list(range(len(X)))
random.shuffle(indices)
X = X[indices]
y = y[indices]

n_val = max(1, int(len(X) * VAL_SPLIT))
X_val = X[:n_val]
y_val = y[:n_val]
X_train = X[n_val:]
y_train = y[n_val:]

print(f"Dataset: {len(X_train)} train examples, {len(X_val)} val examples; Vocab size={len(vocab)}; Classes={len(classes)}")

# ---------- Model init (Xavier) ----------
input_dim = X_train.shape[1]
output_dim = y_train.shape[1]
hidden = HIDDEN_SIZE

def xavier(shape_in, shape_out):
    limit = math.sqrt(6.0 / (shape_in + shape_out))
    return np.random.uniform(-limit, limit, size=(shape_in, shape_out)).astype(np.float32)

W1 = xavier(input_dim, hidden)    # input_dim x hidden
b1 = np.zeros((1, hidden), dtype=np.float32)
W2 = xavier(hidden, output_dim)   # hidden x output_dim
b2 = np.zeros((1, output_dim), dtype=np.float32)

# ---------- Helpers ----------
def relu(z):
    return np.maximum(0, z)

def relu_deriv(z):
    return (z > 0).astype(np.float32)

def softmax(z):
    # z shape (N, C)
    z = z - np.max(z, axis=1, keepdims=True)
    e = np.exp(z)
    return e / (e.sum(axis=1, keepdims=True) + 1e-12)

def forward(X_batch, W1_, b1_, W2_, b2_):
    z1 = np.dot(X_batch, W1_) + b1_          # (B, H)
    a1 = relu(z1)
    z2 = np.dot(a1, W2_) + b2_               # (B, C)
    a2 = softmax(z2)
    return z1, a1, z2, a2

def compute_loss(a2, y_batch):
    # cross-entropy
    return -np.mean(np.sum(y_batch * np.log(a2 + 1e-12), axis=1))

# ---------- Training loop (mini-batch SGD) ----------
best_val = float("inf")
best_weights = None
no_improve = 0
lr = LR

num_train = X_train.shape[0]
num_batches = max(1, (num_train + BATCH_SIZE - 1) // BATCH_SIZE)

for epoch in range(1, EPOCHS + 1):
    # learning rate schedule simple
    if DECAY and epoch > 1:
        lr = LR / (1.0 + DECAY * (epoch-1))

    # shuffle each epoch
    perm = np.random.permutation(num_train)
    X_train = X_train[perm]
    y_train = y_train[perm]

    epoch_loss = 0.0
    for b in range(num_batches):
        start = b * BATCH_SIZE
        end = min(start + BATCH_SIZE, num_train)
        Xb = X_train[start:end]
        yb = y_train[start:end]

        # forward
        z1, a1, z2, a2 = forward(Xb, W1, b1, W2, b2)
        loss = compute_loss(a2, yb)
        epoch_loss += loss * (end - start)

        # backprop (vectorized)
        dz2 = (a2 - yb) / Xb.shape[0]               # (B, C)
        dW2 = np.dot(a1.T, dz2)                    # (H, C)
        db2 = dz2.sum(axis=0, keepdims=True)       # (1, C)

        da1 = np.dot(dz2, W2.T)                    # (B, H)
        dz1 = da1 * relu_deriv(z1)                 # (B, H)
        dW1 = np.dot(Xb.T, dz1)                    # (input_dim, H)
        db1 = dz1.sum(axis=0, keepdims=True)       # (1, H)

        # update weights
        W1 -= lr * dW1
        b1 -= lr * db1
        W2 -= lr * dW2
        b2 -= lr * db2

    epoch_loss /= num_train

    # validation
    _, _, _, a2_val = forward(X_val, W1, b1, W2, b2)
    val_loss = compute_loss(a2_val, y_val)

    if epoch % 10 == 0 or epoch == 1:
        print(f"Epoch {epoch}/{EPOCHS}  train_loss={epoch_loss:.4f}  val_loss={val_loss:.4f}  lr={lr:.5f}")

    # early stopping
    if val_loss < best_val - 1e-6:
        best_val = val_loss
        best_weights = {
            "W1": W1.copy(), "b1": b1.copy(),
            "W2": W2.copy(), "b2": b2.copy()
        }
        no_improve = 0
    else:
        no_improve += 1
        if no_improve >= PATIENCE:
            print(f"[early-stop] No improvement for {PATIENCE} epochs. Stopping at epoch {epoch}.")
            break

# if early stopped, load best weights
if best_weights is not None:
    W1 = best_weights["W1"]
    b1 = best_weights["b1"]
    W2 = best_weights["W2"]
    b2 = best_weights["b2"]

# ---------- Export model ----------
model_data = {
    "input_dim": int(input_dim),
    "hidden_size": int(hidden),
    "output_dim": int(output_dim),
    "words": vocab,
    "classes": classes,
    "W1": W1.tolist(),   # input_dim x hidden
    "b1": b1.reshape(-1).tolist(),
    "W2": W2.tolist(),   # hidden x output_dim
    "b2": b2.reshape(-1).tolist()
}
with open(os.path.join(OUT_DIR, "model_weights.json"), "w", encoding="utf-8") as f:
    json.dump(model_data, f)

# Save pickles already done earlier, but ensure they exist
pickle.dump(vocab, open(os.path.join(OUT_DIR, "words.pkl"), "wb"))
pickle.dump(classes, open(os.path.join(OUT_DIR, "classes.pkl"), "wb"))

print("Exported model_weights.json and pickles to", OUT_DIR)
print("Vocab size:", len(vocab), "Classes:", len(classes))
print("You can test inference with: python inference_purepy.py")

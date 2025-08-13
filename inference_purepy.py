# inference_purepy.py (patched)
# Pure Python forward pass, no numpy required.
import json
import math
import re

MODEL_PATH = "model/model_weights.json"
DEBUG = False   # set True if you want internal debug prints

# ---------- helpers ----------
def clean_text(text):
    # normalize, lower, remove non-alnum except spaces
    text = text.lower()
    # collapse repeated letters (e.g. "hiiiii" -> "hi")
    text = re.sub(r'(.)\1+', r'\1', text)
    text = re.sub(r"[^a-z0-9\s]", " ", text)
    # collapse multiple spaces
    text = re.sub(r"\s+", " ", text).strip()
    tokens = text.split()
    return tokens

def lemmatize_token(token):
    # lightweight lemmatizer fallback: basic rules (not NLTK) to avoid dependency
    if token.endswith("ing") and len(token) > 4:
        return token[:-3]
    if token.endswith("ed") and len(token) > 3:
        return token[:-2]
    return token

def softmax_vec(z):
    # z is list of floats
    m = max(z) if z else 0.0
    exps = [math.exp(x - m) for x in z]
    s = sum(exps) + 1e-12
    return [e / s for e in exps]

def dot(vec_a, vec_b):
    # simple dot product of two equal-length lists
    s = 0.0
    for i in range(len(vec_a)):
        s += vec_a[i] * vec_b[i]
    return s

def matvec_mul(mat, vec):
    # mat: list of rows; compute vec (len rows) dot each column -> out length = cols
    rows = len(mat)
    cols = len(mat[0]) if rows > 0 else 0
    out = [0.0] * cols
    for i in range(rows):
        vi = vec[i]
        if vi == 0.0:
            continue
        row = mat[i]
        for j in range(cols):
            out[j] += vi * row[j]
    return out

# ---------- load model ----------
with open(MODEL_PATH, "r", encoding="utf-8") as f:
    M = json.load(f)

WORDS = M["words"]           # vocab list
CLASSES = M["classes"]       # classes list
W1 = M["W1"]                 # input_dim x hidden
b1 = M["b1"]                 # hidden
W2 = M["W2"]                 # hidden x output_dim
b2 = M["b2"]                 # output_dim

# ---------- inference ----------
def sentence_to_bow(sentence):
    tokens = clean_text(sentence)
    tokens = [lemmatize_token(t) for t in tokens]
    # second normalization: if none matched, try to reduce duplicates further or common corrections
    bow = [0.0] * len(WORDS)
    set_tokens = set(tokens)
    for i, w in enumerate(WORDS):
        if w in set_tokens:
            bow[i] = 1.0

    # if no token matched, try fuzzy-ish fallback: collapse duplicates one more time and retry
    if sum(bow) == 0 and tokens:
        tokens2 = [re.sub(r'(.)\1+', r'\1', t) for t in tokens]
        set_tokens2 = set(tokens2)
        for i, w in enumerate(WORDS):
            if w in set_tokens2:
                bow[i] = 1.0
    return bow

def forward_pass(bow):
    # hidden = ReLU( bow @ W1 + b1 )
    # z1 shape = hidden
    z1 = matvec_mul(W1, bow)   # mat rows = input_dim, vec length = input_dim
    # add bias
    for j in range(len(z1)):
        z1[j] += b1[j]
    # ReLU
    a1 = [x if x > 0 else 0.0 for x in z1]

    # output logits: a1 @ W2 + b2
    z2 = matvec_mul(W2, a1)  # W2 rows = hidden, vec length = hidden
    for j in range(len(z2)):
        z2[j] += b2[j]

    probs = softmax_vec(z2)
    return probs

def _keyword_fallback(sentence):
    s = sentence.lower()
    # greeting keywords
    greetings = ["hi", "hello", "hey", "hiya", "hii", "yo", "greetings", "howdy"]
    for g in greetings:
        if re.search(r"\b" + re.escape(g) + r"\b", s):
            if "greeting" in CLASSES:
                return [("greeting", 1.0)]
            else:
                return [("unknown", 0.0)]
    # medical keywords
    med = ["bleed", "blood", "injur", "fracture", "unconscious", "hurt", "need medic", "sos", "help"]
    for k in med:
        if k in s:
            if "medical_emergency" in CLASSES:
                return [("medical_emergency", 1.0)]
            else:
                return [("request_assistance", 1.0)] if "request_assistance" in CLASSES else [("unknown", 0.0)]
    # tech/help keywords
    tech = ["wifi", "internet", "connection", "battery", "restart", "error", "bug", "signal"]
    for k in tech:
        if k in s:
            if "technical_help" in CLASSES:
                return [("technical_help", 1.0)]
            else:
                return [("unknown", 0.0)]
    return [("unknown", 0.0)]

def predict_top(sentence, topk=1, threshold=0.2):
    bow = sentence_to_bow(sentence)
    # if bow is all zeros, use keyword fallback (avoid bias-driven wrong label)
    if sum(bow) == 0:
        if DEBUG:
            print("[debug] BOW all zeros -> using keyword fallback")
        return _keyword_fallback(sentence)

    probs = forward_pass(bow)
    pairs = list(enumerate(probs))
    pairs.sort(key=lambda x: x[1], reverse=True)
    out = []
    for idx, p in pairs[:topk]:
        if p >= threshold:
            out.append((CLASSES[idx], p))
    # if nothing above threshold, still return top-1 but with its score
    if not out and pairs:
        idx, p = pairs[0]
        out.append((CLASSES[idx], p))
    return out

# ---------- CLI quick test ----------
if __name__ == "__main__":
    print("Loaded model with", len(WORDS), "words and", len(CLASSES), "classes.")
    while True:
        s = input("> ").strip()
        if not s:
            continue
        if s in ("/exit","/quit"):
            break
        out = predict_top(s, topk=3, threshold=0.1)
        if not out:
            print("No confident intent (fallback).")
        else:
            for tag, prob in out:
                print(f"{tag}  ({prob*100:.1f}%)")

def predict_intent(text):
    # Return list of (tag, probability) for detected intents
    results = predict_top(text, topk=3, threshold=0.1)
    if not results:
        return [("unknown", 0.0)]
    return results

def medic_triage(text):
    # Simple keyword-based triage like your fallback
    s = text.lower()
    urgent_kw = ["severe bleeding", "profuse bleeding", "no pulse", "heart stopped", "can't breathe", "chest pain", "i am dying", "unconscious"]
    moderate_kw = ["vomit", "vomiting", "nausea", "dizzy", "dizziness", "faint", "fever", "breathless", "shortness of breath", "seizure"]
    mild_kw = ["cut", "small cut", "scratch", "sprain", "minor burn", "bruise", "itch", "headache", "cold", "cough"]
    for kw in urgent_kw:
        if kw in s:
            return "urgent"
    for kw in moderate_kw:
        if kw in s:
            return "moderate"
    for kw in mild_kw:
        if kw in s:
            return "mild"
    return "unknown"

# Tesera

**Verify where any image or video came from. Prove who made it and what changed.**

Tesera is an open-source Python SDK that creates cryptographic provenance records for digital media. When an image is created or edited, Tesera generates a signed commit containing a fingerprint of the file, a timestamp, and a link to previous versions. Anyone can check that record to verify the file is authentic and unmodified.

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/downloads/)
[![Tests](https://img.shields.io/badge/tests-121_passed-brightgreen.svg)]()

---

## Quickstart
```bash
pip install tes-core
```
```python
from tes_core import Tesera

t = Tesera()

# Sign a new image — one line in your pipeline
commit = t.commit(image_bytes, operation="create")

# Verify an image's provenance
result = t.verify(image_bytes)

# Check full history
history = t.history(image_bytes)
```

That's it. Every image that passes through your pipeline gets a cryptographic provenance record — hashed, signed, and stored — without you thinking about it again.

---

## How It Works

Tesera creates **commits** — signed records that form a chain of custody for media files.
```
Photo taken     →  Cropped in editor  →  Published on news site
  commit #1           commit #2              commit #3
  (create)         (edit, parent: #1)     (edit, parent: #2)
```

Each commit contains:
- **SHA-256 hash** of the media file (the fingerprint)
- **Ed25519 signature** proving the record hasn't been tampered with
- **Parent reference** linking to the previous version
- **Timestamp** and **signer identity**

No images are stored. Only fingerprints and signed metadata.

---

## Integration Patterns

### Image Generation (AI, cameras, editing software)

Integrate once. Every image produced gets signed automatically.
```python
from tes_core import Tesera

# Initialize once at service startup
tesera = Tesera(
    key_name="novapix-prod",
    media_type="image/png"
)

# Inside your existing image generation handler:
def generate_image(prompt):
    image_bytes = model.generate(prompt)
    tesera.commit(image_bytes, operation="create",
        metadata={"software": "NovaPix v2.1"})
    return upload_to_s3(image_bytes)
```

### Image Editing

Wire Tesera into your open/save hooks. Chain linking happens automatically.
```python
# When user opens a file
original_commit = tesera.lookup(input_file)

# When user saves — Tesera handles the rest
edit_commit = tesera.commit_edit(
    original=input_file,
    edited=output_bytes
)
```

If the input file has existing provenance, the edit links back to it. If it doesn't (an image from outside the Tesera ecosystem), Tesera creates an honest import record first — recording that the file was received without claiming it's authentic — then links the edit on top.
```python
# Explicit unverified upload handling
import_commit, edit_commit = tesera.commit_edit_from_upload(
    original=input_file,
    edited=output_bytes
)
```

---

## Key Management

**Individual developers** — zero configuration:
```python
t = Tesera()  # Key auto-generated on first use
```

**Organizations** — shared key across infrastructure:
```bash
export TESERA_PRIVATE_KEY="-----BEGIN PRIVATE KEY-----
..."
```
```python
t = Tesera()  # Picks up env var automatically
```

**From a secret manager:**
```python
t = Tesera(private_key=vault.get("tesera-key"))
```

Access your signing identity:
```python
print(t.public_key)        # PEM-encoded public key
print(t.key_fingerprint)   # 32-char hex fingerprint
```

Key loading priority: explicit parameter → environment variable → local filesystem → auto-generate.

---

## Relationship to C2PA

[C2PA](https://c2pa.org) is an industry standard for embedding provenance metadata directly into media files. Tesera complements C2PA by providing a shared registry where provenance records can be discovered and verified across platforms.

**C2PA** = the passport you carry with you (embedded in the file).
**Tesera** = the immigration database where anyone can look up your travel history.

Tesera is designed to be compatible with C2PA. Organizations already producing C2PA manifests can have their provenance data indexed without changing their workflow.

---

## Project Status

The core SDK is **functional and tested** — 121 tests passing against a formal specification with validated test vectors.

| Component | Status |
|-----------|--------|
| Media hashing (SHA-256, streaming) | ✅ Complete |
| Key management (Ed25519, env var, auto-generate) | ✅ Complete |
| Commit creation & verification | ✅ Complete |
| Chain traversal & provenance lookup | ✅ Complete |
| Local storage (SQLite) | ✅ Complete |
| Edit workflow & import operations | ✅ Complete |
| CLI tool | 🔜 Next |
| C2PA bridge | 🔜 Planned |
| Public registry | 🔜 Planned |
| TypeScript SDK | 🔜 Planned |

---

## Architecture
```
packages/core/src/tes_core/
├── api.py        # Public API — the Tesera class
├── hash.py       # SHA-256 hashing, media type detection
├── sign.py       # Ed25519 key generation, signing, verification
├── commit.py     # Commit creation, verification, serialization
├── store.py      # Storage interface, SQLite & in-memory backends
├── chain.py      # Provenance chain traversal, common ancestor
└── __init__.py   # Public exports
```

---

## Development

Requires [uv](https://docs.astral.sh/uv/) (`brew install uv` or see the [uv docs](https://docs.astral.sh/uv/getting-started/installation/)).
```bash
git clone https://github.com/tesann/Tesera.git
cd Tesera
uv sync --extra dev
uv run pytest
```

---

## License

[Apache 2.0](LICENSE) — free to use in commercial and open-source projects.

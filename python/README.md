# Python example

Generates an AdvaView launch token using [jwcrypto](https://github.com/latchset/jwcrypto).
See the [top-level README](../README.md) for the token format.

## Requirements

- Python 3.9+

## Run

```
python -m venv .venv
# Windows: .venv\Scripts\activate    macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt

python generate_token.py \
    --username jane.doe@example.com \
    --suid 1.2.840.113619.2.55.3.1234 \
    --accessKeyId <your key id> \
    --accessKeySecret <your key secret> \
    --expireAfter 300
```

## Where to look

Everything is in [`generate_token.py`](generate_token.py), laid out as three steps:
`read_inputs()` → `build_payload()` → `sign()` / `encrypt()`.

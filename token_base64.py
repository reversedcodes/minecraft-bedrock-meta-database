import base64, json

with open("tokens.json", "r", encoding="utf-8") as f:
    raw = f.read()

encoded = base64.b64encode(raw.encode("utf-8")).decode("utf-8")
print(encoded)

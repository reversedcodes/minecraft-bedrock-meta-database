import base64

with open("tokens.json", "r", encoding="utf-8") as f:
    data = f.read()

encoded = base64.b64encode(data.encode("utf-8")).decode("utf-8")

with open("tokens_b64.txt", "w", encoding="utf-8") as f:
    f.write(encoded)

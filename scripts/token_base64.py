import base64

from constant import ROOT_PATH, logging

logger = logging.getLogger("TokenBase64Encoder")

with open(ROOT_PATH / "tokens.json", "r", encoding="utf-8") as f:
    data = f.read()

logger.info("Encoding tokens.json to Base64")

encoded = base64.b64encode(data.encode("utf-8")).decode("utf-8")

with open(ROOT_PATH / "tokens_b64.txt", "w", encoding="utf-8") as f:
    f.write(encoded)

logger.info("Encoding complete. Output written to tokens_b64.txt")

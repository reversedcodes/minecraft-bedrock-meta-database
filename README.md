# 🧱 Minecraft Bedrock Metadata Database

An automated updater for Minecraft Bedrock clients and servers — and more.

---

## 📦 Fetching Data

```bash
# Client example
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/refs/heads/main/bedrock/client/gdk/{release_type}/{arch}/{version}/metadata.json

# Version index
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/refs/heads/main/bedrock/client/gdk/versions.json
```

---

## 📁 Structure

```
bedrock/
 ├── client/
 │    ├── gdk/
 │    │    ├── release/<arch>/<version>/metadata.json
 │    │    ├── preview/<arch>/<version>/metadata.json
 │    │    └── versions.json
 │    └── uwp/
 │    │    ├── release/<arch>/<version>/metadata.json
 │    │    ├── preview/<arch>/<version>/metadata.json
 │         └── versions.json
 └── server/
      │── windows/<version>/metadata.json
      │── linux/<version>/metadata.json
      └── versions.json
```

---

## 📜 License
This project is licensed under the [Apache License 2.0](LICENSE).  
You are free to use, modify, and distribute this software under the terms of the license.

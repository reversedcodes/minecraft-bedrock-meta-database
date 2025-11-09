# 🧱 Minecraft Bedrock Metadata Database

An auto-updater for Minecraft Bedrock (GDK) builds using the official Xbox Live Update API.  
Runs every **12 hours** via GitHub Actions and stores all versions separately by architecture.

---

## ⚙️ Features
- Fetches metadata directly from `packagespc.xboxlive.com`
- Automatically refreshes Xbox OAuth tokens
- Stores all versions sorted by architecture (x64, x86, arm)
- Generates version JSON files for simple data access

---

## 📦 Fetching Data

```bash
# client example
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/refs/heads/main/bedrock/client/{release_type}/{arch}/{version}/metadata.json

# version index
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/refs/heads/main/bedrock/client/versions.json
```

---

## 📁 Structure

```
bedrock/
 └── client/
      ├── release/x64/<version>/metadata.json
      ├── preview/arm/<version>/metadata.json
      └── versions.json
```
---

## 📜 License
This project is licensed under the [Apache License 2.0](LICENSE).  
You are free to use, modify, and distribute this software under the terms of the license.
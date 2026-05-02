# Minecraft Bedrock Metadata Database

An automated metadata database for Minecraft Bedrock clients and servers.

---

## Fetching Data

```bash
# GDK client metadata
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/main/bedrock/client/{release_type}/gdk/{version}.json

# UWP client metadata
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/main/bedrock/client/{release_type}/uwp/{version}.json

# Server metadata
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/main/bedrock/server/{release_type}/{version}.json

# Client version index
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/main/bedrock/client/versions.json

# Server version index
curl -s https://raw.githubusercontent.com/reversedcodes/minecraft-bedrock-meta-database/main/bedrock/server/versions.json
```

`{release_type}` = `release` or `preview`

---

## Structure

```
bedrock/
 ├── client/
 │    ├── versions.json
 │    ├── release/
 │    │    ├── gdk/{version}.json
 │    │    └── uwp/{version}.json
 │    └── preview/
 │         ├── gdk/{version}.json
 │         └── uwp/{version}.json
 └── server/
      ├── versions.json
      ├── release/{version}.json
      └── preview/{version}.json
```

---

## File Formats

**GDK client** (`bedrock/client/{release_type}/gdk/{version}.json`)

```json
{
    "binaries": {
        "arch": {
            "x64": {
                "file_name": "...",
                "file_size": 0,
                "version": "1.26.3.1",
                "version_raw": "1.26.301.0",
                "release_type": "release",
                "arch": "x64",
                "urls": ["..."],
                "file_hash": "..."
            }
        }
    }
}
```

**UWP client** (`bedrock/client/{release_type}/uwp/{version}.json`)

```json
{
    "binaries": {
        "arch": {
            "x64": {
                "appx": { "file_name": "...", "file_size": 0, "version": "1.9.0.15", "file_hash": "..." },
                "eappx": {}
            },
            "x86": {
                "appx": { "..." },
                "eappx": { "..." }
            },
            "arm": {
                "appx": { "..." },
                "eappx": { "..." }
            }
        }
    }
}
```

**Server** (`bedrock/server/{release_type}/{version}.json`)
```json
{
    "binaries": {
        "windows": {
            "file_name": "bedrock-server-1.26.14.1.zip",
            "file_size": 0,
            "version": "1.26.14.1",
            "url": "...",
            "release_type": "release",
            "file_hash": "...",
            "file_executable_hash": "..."
        },
        "linux": { "..." }
    }
}
```

---

## License
This project is licensed under the [Apache License 2.0](LICENSE).  
You are free to use, modify, and distribute this software under the terms of the license.

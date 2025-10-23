## ratCORE.CryptedConfig

**ratCORE.CryptedConfig** is a C# library for securely storing configuration data and sensitive application settings.  
It uses **AES-GCM encryption**, supports both **passphrase** and **machine-bound secrets**, and authenticates the file header via **Associated Data (AAD)** to prevent tampering.

---

### 🚀 Features

- **Flexible Data Types**  
  Supports a wide range of types including `string`, `int`, `bool`, `enum`, `DateTime`, `Guid`, `Uri`, `byte[]`, and more.  
  Automatic type conversion during serialization and deserialization.

- **JSON-based Storage**  
  - Human-readable and portable format (when unencrypted).  
  - Uses `System.Text.Json` with UTF-8 encoding for performance and simplicity.

- **AES-GCM Encryption**  
  - Authenticated encryption providing both confidentiality and integrity.  
  - The file header (MAGIC, Version, Flags, Iterations, Salt, Nonce) is included as *Associated Data* (AAD).  
  - Any tampering or corruption is immediately detected via authentication tag verification.

- **Combined Key Derivation (KDF)**  
  - Derives a Key Encryption Key (KEK) via PBKDF2 from the passphrase and/or machine secret.  
  - Generates a Data Encryption Key (DEK) via HMAC from a context label (`ratCORE-DEK-v1`).  
  - Supports passphrase-only, machine-secret-only, or combined dual-factor mode.

- **Machine Secret File**  
  - Optionally stores a random machine-specific secret (`chmod 600` on Linux).  
  - By default, the machine secret is stored in the same directory as the encrypted config file (e.g. `config.sec.secret`).
  - It is **recommended** to move it to a secure location (e.g. `~/.local/state/ratcore/secret.key`).
  - If the file is lost, decryption becomes impossible — ensuring data confidentiality even with full file access.

- **Tamper-Protected Header**  
  - **MAGIC** identifier: `RCCC` (ratCORE Crypted Config).  
  - Versioned format to allow future upgrades.  
  - Bitmask for encryption flags (`0x1` = Passphrase, `0x2` = MachineSecret, `0x3` = Both).

- **Clear Error Handling**  
  Detailed exceptions for:
  - Wrong passphrase or missing machine secret  
  - Corrupted or truncated file (failed GCM authentication tag)  
  - Unsupported format version  

---

### 🧩 Example Usage / Quick Start

```csharp
using ratCORE.CryptedConfig;

var cfg = new CryptedConfig();
cfg.Add("Username", "Admin");
cfg.Add("RetryCount", 3);
cfg.Add("EnableLogging", true);

// Save (passphrase + machine secret; PBKDF2 iterations configurable)
cfg.Save(
    configFilePath: "config.sec",
    passphrase: "myStrongPassword",             // optional (null = disabled)
    machineSecretPath: null,                    // null = use same path as config file
    pbkdf2Iterations: 300_000
);

// Load
var loaded = CryptedConfig.Load(
    configFilePath: "config.sec",
    passphrase: "myStrongPassword",             // must match if set
    machineSecretPath: null                     // must exist if required by flags
);

// Access values
Console.WriteLine(loaded.Get("Username"));      // "Admin"
Console.WriteLine(loaded.Count);                // number of entries
```

---

### ⚠️ Error Handling

`ratCORE.CryptedConfig` provides clear and descriptive exceptions to simplify debugging and error diagnostics.

#### Common Exceptions

| Exception | Description | Thrown by |
|------------|--------------|------------|
| **`ConfigFileNotFoundException`** | The specified encrypted configuration file could not be found. | `Load()` |
| **`MachineSecretFileNotFoundException`** | The machine secret file is missing or inaccessible. Without this file, the configuration cannot be decrypted. | `Load()` |
| **`ItemAlreadyExistsException`** | A configuration entry with the same name already exists. | `Add()` / `SetName()` |
| **`InvalidDataException`** | The file header is invalid or corrupted. Can also occur if decryption fails (wrong passphrase, wrong secret, or tampered file). | `Load()` |
| **`NotSupportedException`** | The file uses an unsupported version number. | `Load()` |
| **`EndOfStreamException`** | The file is truncated or incomplete (e.g. missing ciphertext or tag). | `Load()` |
| **`IOException` / `UnauthorizedAccessException`** | Generic file access or permission errors during read/write operations. | `Save()` / `Load()` |

---

#### Typical Error Scenarios

| Scenario | Cause | Resolution |
|-----------|--------|------------|
| **Wrong passphrase or missing secret** | AES-GCM authentication fails because the derived decryption key does not match the stored tag. | Check passphrase and ensure the correct machine secret file is used. |
| **Corrupted file** | File was partially written or modified after encryption. | Restore from a valid backup. |
| **Unsupported version** | The file was created with a newer format version not recognized by the current library. | Update to the latest version of `ratCORE.CryptedConfig`. |
| **Duplicate entry** | Attempt to add a key that already exists. | Use `Set()` or rename the entry. |
| **Permission error** | Insufficient file access rights or read-only location. | Adjust filesystem permissions (Linux/macOS: `chmod 600`). |

---

#### Recommended Error Handling Pattern

```csharp
try
{
    var cfg = CryptedConfig.Load("config.sec", passphrase: "mySecret");
    Console.WriteLine($"Loaded {cfg.Count} entries.");
}
catch (MachineSecretFileNotFoundException ex)
{
    Console.Error.WriteLine("Missing machine secret: " + ex.Message);
}
catch (InvalidDataException ex)
{
    Console.Error.WriteLine("Decryption failed or file corrupted: " + ex.Message);
}
catch (NotSupportedException ex)
{
    Console.Error.WriteLine("Unsupported file version: " + ex.Message);
}
catch (Exception ex)
{
    Console.Error.WriteLine("Unexpected error: " + ex.Message);
}
```

> If you suspect a decryption failure, inspect the `InnerException` of `InvalidDataException`.  
AES-GCM will throw a `CryptographicException` if authentication fails due to an invalid key or tampered data.

---

### ⚙️ File Header Layout

```
MAGIC        :  4 bytes = 'RCCC'  
VERSION      :  1 byte  = Format version  
FLAGS        :  1 byte  = Bitmask (0x1=Passphrase, 0x2=MachineSecret, 0x3=Both)  
ITERATIONS   :  4 bytes = PBKDF2 iteration count (int32, little-endian)  
SALT         : 16 bytes = Random KDF salt  
NONCE        : 12 bytes = AES-GCM initialization vector  
CIPHERTEXT   :  x bytes = Encrypted JSON payload  
TAG          : 16 bytes = AES-GCM authentication tag  
```

---

### 🧱 Technical Overview

| Component | Purpose |
|------------|----------|
| **PBKDF2 (SHA-256)** | Derives the Key Encryption Key (KEK) from passphrase and/or machine secret. |
| **HMAC-SHA256** | Generates the Data Encryption Key (DEK) using the label `ratCORE-DEK-v1`. |
| **AES-GCM** | Encrypts and authenticates the serialized JSON data. |
| **AAD (Associated Data)** | Binds the header fields to the ciphertext to prevent manipulation. |

---

### 🖥️ Default Secret File Locations

| Platform | Path |
|-----------|------|
| **Windows** | `%APPDATA%\ratcore\secret.key` |
| **Linux** | `~/.local/state/ratcore/secret.key` |
| **macOS** | `~/.local/state/ratcore/secret.key` |

> 🛡️ It is **recommended** to keep the machine secret file in a secure location, accessible only by the application user.

---

### 🛠️ System Requirements

- .NET 8 or higher  
- Supported platforms: **Windows**, **Linux**, **macOS**  
- No external dependencies  

---

### 🧩 About

This project is part of the **ratCORE** framework — a collection of libraries designed for robust, cross-platform, and secure .NET development.

---

**License:** Creative Commons Attribution 4.0 International (CC BY 4.0)  
**Copyright © 2025 ratware**

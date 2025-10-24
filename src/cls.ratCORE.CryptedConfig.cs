/* ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Program:                         ratCORE.CryptedConfig
 * Description:                     Manage encrypted application config via AES-GCM algorithm.
 * Current Version:                 1.0.9398.867 (24.09.2025)
 * Company:                         ratware
 * Author:                          Tom V. (ratware)
 * Email:                           info@ratware.de
 * Copyright:                       © 2025 ratware
 * License:                         Creative Commons Attribution 4.0 International (CC BY 4.0)
 * License URL:                     https://creativecommons.org/licenses/by/4.0/
 * Filename:                        cls.ratCORE.CryptedConfig.cs
 * Language:                        C# (.NET 8)
 * 
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * History:
 * 
 *     - 24.09.2025 - Tom V. (ratware) - Version 1.0.9398.867
 *       Reviewed and approved
 * 
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Current file structure (Version 1):
 * 
 * MAGIC        :  4 bytes = 'RCCC' (ratCORE Crypted Config)
 * VERSION      :  1 byte  = 1
 * FLAGS        :  1 byte  = Bitmask: 0x1=Passphrase only, 0x2=MachineSecret only, 0x3=Passphrase+MachineSecret
 * ITERATIONS   :  4 bytes = PBKDF2-Iterations (int32, e.g. 200_000)
 * SALT         : 16 bytes = for KDF
 * NONCE        : 12 bytes = for AES-GCM
 * CIPHERTEXT   :  x bytes = encrypted JSON-Bytes
 * TAG          : 16 bytes = GCM-Tag
 * 
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 * 
 * Notes:
 * 
 *     A passphrase and/or a machine secret file is used for encryption and decryption.
 *     The machine secret file is always created during encryption.
 *     By default, this file is created in the same directory as the config file.
 *     e.g.
 *       - Encrypted Config File ..: "/home/user/myapp/myapp.config"
 *       - Machine Secret File ....: "/home/user/myapp/myapp.config.secret"
 *     However, it is recommended to choose a secure storage location for the machine secret file.
 *     e.g.
 *       - Encrypted Config File ..: "/home/user/myapp/myapp.config"
 *       - Machine Secret File ....: "/home/user/.config/myapp.config.secret" or "/home/user/.local/myapp.config.secret"
 *     Important! Without this file, the config file cannot be decrypted.
 * 
 *     To add additional versions, the "KDFLabel" string array must be extended by another entry.
 *     In addition, the IF statement in the "Load()" method must be extended with another ELSE statement to load the old and current versions.
 *     The "Save()" method must also be adapted to reflect the new version.
 * 
 */

using System.Buffers.Binary;
using System.ComponentModel;
using System.Globalization;
using System.Security.Cryptography;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ratCORE.CryptedConfig
{
    #region Exceptions

#if NETFRAMEWORK
    [Serializable]
#endif
    public class ItemAlreadyExistsException : Exception
    {
        public ItemAlreadyExistsException() { }
        public ItemAlreadyExistsException(string message) : base(message) { }
        public ItemAlreadyExistsException(string? message, Exception? innerException) : base(message, innerException) { }
#if NETFRAMEWORK
        protected ItemAlreadyExistsException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) { }
#endif
    }

#if NETFRAMEWORK
    [Serializable]
#endif
    public class MachineSecretFileNotFoundException : Exception
    {
        public MachineSecretFileNotFoundException() { }
        public MachineSecretFileNotFoundException(string message) : base(message) { }
        public MachineSecretFileNotFoundException(string? message, Exception? innerException) : base(message, innerException) { }
#if NETFRAMEWORK
        protected MachineSecretFileNotFoundException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) { }
#endif
    }

#if NETFRAMEWORK
    [Serializable]
#endif
    public class ConfigFileNotFoundException : Exception
    {
        public ConfigFileNotFoundException() { }
        public ConfigFileNotFoundException(string message) : base(message) { }
        public ConfigFileNotFoundException(string? message, Exception? innerException) : base(message, innerException) { }
#if NETFRAMEWORK
        protected ConfigFileNotFoundException(
            SerializationInfo info,
            StreamingContext context) : base(info, context) { }
#endif
    }

    #endregion

    /// <summary>Represents a single config item.</summary>
    public class ConfigEntry
    {
        /// <summary>Gets or sets a name of this entry.</summary>
        public string Name { get; set; } = string.Empty;

        /// <summary>Gets or sets a description of this entry.</summary>
        public string Description { get; set; } = string.Empty;

        /// <summary>Gets the raw value of this entry.</summary>
        [JsonInclude]
        public string? RawValue { get; private set; }

        /// <summary>Gets the type of the value of this entry.</summary>
        [JsonInclude]
        public string ValueType { get; private set; } = "System.String";

        /// <summary>Gets or sets a value of this entry.</summary>
        [JsonIgnore]
        public object? Value
        {
            get => ConvertFromString(this.RawValue, this.ValueType);
            set
            {
                if (value is null)
                {
                    // null, retain type
                    this.RawValue = null;
                    return;
                }
                this.ValueType = value.GetType().FullName ?? "System.String";
                this.RawValue = ConvertToString(value);
            }
        }

        /// <summary>Gets the converted raw value as data type.</summary>
        /// <param name="raw">The raw value.</param>
        /// <param name="typeName">The data type.</param>
        private static object? ConvertFromString(string? raw, string typeName)
        {
            if (raw is null) return null;

            if (string.IsNullOrWhiteSpace(typeName)) typeName = "System.String";
            var t = Type.GetType(typeName) ?? typeof(string);

            // process Nullable<T>
            var underlying = Nullable.GetUnderlyingType(t);
            var target = underlying ?? t;

            try
            {
                if (target == typeof(string)) return raw;
                if (target == typeof(bool)) return bool.Parse(raw);
                if (target == typeof(int)) return int.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(long)) return long.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(short)) return short.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(byte)) return byte.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(double)) return double.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(float)) return float.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(decimal)) return decimal.Parse(raw, CultureInfo.InvariantCulture);
                if (target == typeof(DateTime)) return DateTime.Parse(raw, CultureInfo.InvariantCulture, DateTimeStyles.RoundtripKind);
                if (target == typeof(Guid)) return Guid.Parse(raw);
                if (target == typeof(Uri)) return new Uri(raw, UriKind.RelativeOrAbsolute);
                if (target == typeof(byte[])) return Convert.FromBase64String(raw);
                if (target.IsEnum) return Enum.Parse(target, raw, ignoreCase: true);

                // fallback: TypeConverter
                var tc = TypeDescriptor.GetConverter(target);
                if (tc.CanConvertFrom(typeof(string))) return tc.ConvertFromInvariantString(raw);

                // last fallback
                return Convert.ChangeType(raw, target, CultureInfo.InvariantCulture);
            }
            catch
            {
                // on error, return raw value as string
                return raw;
            }
        }

        /// <summary>Gets the value as converted string.</summary>
        /// <param name="value">The value.</param>
        private static string ConvertToString(object value)
        {
            switch (value)
            {
                case string s: return s;
                case bool b: return b.ToString();
                case Enum e: return e.ToString(); // Name
                case DateTime dt: return dt.ToString("O", CultureInfo.InvariantCulture); // ISO8601 Roundtrip
                case Guid g: return g.ToString("D");
                case Uri uri: return uri.ToString();
                case byte[] bytes: return Convert.ToBase64String(bytes);
                default:
                    // Primitive / IFormattable
                    if (value is IFormattable f) return f.ToString(null, CultureInfo.InvariantCulture);

                    // fallback: TypeConverter
                    var tc = TypeDescriptor.GetConverter(value.GetType());
                    if (tc.CanConvertTo(typeof(string))) return tc.ConvertToInvariantString(value)!;

                    // last fallback
                    return value.ToString() ?? string.Empty;
            }
        }
    }

    /// <summary>Represents a list of config items and methods to manage the items.</summary>
    public class CryptedConfig
    {
#if LINUX
        [DllImport("libc", SetLastError = true, EntryPoint = "chmod")]
        private static extern int chmod(string path, int mode); // 0600 = 0x180 (S_IRUSR|S_IWUSR)
#elif MACOS
        [DllImport("/usr/lib/libSystem.dylib", SetLastError = true, EntryPoint = "chmod")]
        private static extern int chmod(string pathname, uint mode);
#endif

        /// <summary>Gets the magic bytes.</summary>
        private static readonly byte[] MAGIC = new byte[] { (byte)'R', (byte)'C', (byte)'C', (byte)'C' };

        /// <summary>Gets the encryption flags.</summary>
        [Flags]
        private enum EncFlags : byte { None = 0, Passphrase = 1, MachineSecret = 2, PassphraseWithMachineSecret = 3 }

        /// <summary>Gets the KDF labels for each version.</summary>
        private static readonly string[] KDFLabel =
        {
            "ratCORE-DEK-v1"
            /* Version      : 1
             * KDF-Label    : ratCORE-DEK-v1
             * --------------------------------------------
             * Header-Layout:
             * 
             * MAGIC        :  4 bytes = 'RCCC' (ratCORE Crypted Config)
             * VERSION      :  1 byte  = 1
             * FLAGS        :  1 byte  = Bitmask: 0x1=Passphrase only, 0x2=MachineSecret only, 0x3=Passphrase+MachineSecret
             * ITERATIONS   :  4 bytes = PBKDF2-Iterations (int32, e.g. 200_000)
             * SALT         : 16 bytes = for KDF
             * NONCE        : 12 bytes = for AES-GCM
             * CIPHERTEXT   :  x bytes = encrypted JSON-Bytes
             * TAG          : 16 bytes = GCM-Tag
             */
        };

        /// <summary>Gets the current version of the encrypted config file.</summary>
        private readonly byte VERSION = (byte)KDFLabel.Length;

        /// <summary>Contains a list of all config items.</summary>
        [JsonInclude]
        public List<ConfigEntry> ConfigEntries { get; private set; } = new List<ConfigEntry>();

        /// <summary>Contains the Json serializer options.</summary>
        private static readonly JsonSerializerOptions JsonOpts = new()
        {
            WriteIndented = false,
            PropertyNamingPolicy = null /* retain PascalCase */,
            IncludeFields = false
        };

        /// <summary>Add a new config item.</summary>
        /// <param name="name">The name of the new item.</param>
        /// <param name="value">The value of the new item.</param>
        /// <param name="description">The description of the new item.</param>
        public void Add(string name, object? value, string? description = null)
        {
            if (this.Exists(name)) throw new ItemAlreadyExistsException($"Name '{name}' already exists!");

            var e = new ConfigEntry
            {
                Name = name,
                Description = description ?? string.Empty,
                Value = value
            };
            this.ConfigEntries.Add(e);
        }

        /// <summary>Gets whether a config item already exists.</summary>
        /// <param name="name">The name of the item.</param>
        public bool Exists(string name)
            => this.ConfigEntries.Any(e => e.Name == name);

        /// <summary>Gets the count of all config items.</summary>
        [JsonIgnore]
        public int Count
            => this.ConfigEntries.Count;

        /// <summary>Gets the value of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        public object? Get(string name)
            => this.ConfigEntries.Find(e => e.Name == name)?.Value;

        /// <summary>Gets the description of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        public string? GetDescription(string name)
            => this.ConfigEntries.Find(e => e.Name == name)?.Description;

        /// <summary>Gets the raw value of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        public string? GetRawValue(string name)
            => ConfigEntries.Find(e => e.Name == name)?.RawValue;

        /// <summary>Gets the value type of the value of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        public string GetValueType(string name)
            => this.ConfigEntries.Find(e => e.Name == name)!.ValueType;

        /// <summary>The value of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        /// <param name="newValue">The new value of the item.</param>
        public void Set(string name, object? newValue)
            => this.ConfigEntries.Where(e => e.Name == name).ToList().ForEach(s => s.Value = newValue);

        /// <summary>The name of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        /// <param name="newName">The new name of the item.</param>
        public void SetName(string name, string newName)
        {
            if (this.Exists(name)) throw new ItemAlreadyExistsException($"Name '{name}' already exists!");

            this.ConfigEntries.Where(e => e.Name == name).ToList().ForEach(s => s.Name = newName);
        }

        /// <summary>The description of a config item.</summary>
        /// <param name="name">The name of the item.</param>
        /// <param name="newDescription">The new description of the item.</param>
        public void SetDescription(string name, string newDescription)
            => this.ConfigEntries.Where(e => e.Name == name).ToList().ForEach(s => s.Description = newDescription);

        /// <summary>Remove a config item by its name.</summary>
        /// <param name="name">The name of the item.</param>
        public void Remove(string name)
        {
            int index = this.ConfigEntries.FindIndex(e => e.Name == name);
            if (index >= 0) this.ConfigEntries.RemoveAt(index);
        }

        /// <summary>Remove a config item by its index.</summary>
        /// <param name="index">The index of the item.</param>
        public void RemoveAt(int index)
        {
            if (index >= 0 && index < this.ConfigEntries.Count) this.ConfigEntries.RemoveAt(index);
        }

        /// <summary>Clears the list of config items.</summary>
        public void Clear()
            => this.ConfigEntries.Clear();

        /// <summary>Gets a byte array of random bytes.</summary>
        /// <param name="len">The length of the byte array.</param>
        private static byte[] RandomBytes(int len)
        {
            var b = new byte[len];
            RandomNumberGenerator.Fill(b);
            return b;
        }

        /// <summary>Gets the default path of the machine secret file.</summary>
        /// <param name="configPath">The path of the config file.</param>
        private static string GetDefaultSecretPath(string configPath)
            => Path.Combine(Path.GetDirectoryName(configPath)!, Path.GetFileName(configPath) + ".secret");

        /// <summary>Try to set user rights to file.</summary>
        /// <param name="path">The path of the machine secret file.</param>
        private static void TryChmod600(string path)
        {
            try
            {
#if WINDOWS
                // no POSIX file permissions on windows
                return;
#elif MACOS
                const int S_IRUSR = 0x100; // 0400
                const int S_IWUSR = 0x80; // 0200
                uint mode = S_IRUSR | S_IWUSR; // 0600
                chmod(path, mode);
#elif LINUX
                const uint S_IRUSR = 0x100; // 0400
                const uint S_IWUSR = 0x80; // 0200
                uint mode = S_IRUSR | S_IWUSR; // 0600
                chmod(path, mode);
#else
                // other OS
                return;
#endif            
            }
            catch
            {
                // on error, do nothing
            }
        }

        /// <summary>Gets or creates the machine secrets.</summary>
        /// <param name="path">The path of the machine secret file.</param>
        private static byte[] GetOrCreateMachineSecret(string path)
        {
            Directory.CreateDirectory(Path.GetDirectoryName(path)!);
            if (!File.Exists(path))
            {
                var raw = RandomBytes(32);
                File.WriteAllBytes(path, raw);
                TryChmod600(path);
            }
            return File.ReadAllBytes(path);
        }

        /// <summary>Derive the key encryption key.</summary>
        /// <param name="salt">The salt.</param>
        /// <param name="iterations">The PBKDF2 iterations.</param>
        /// <param name="passphrase">The passphrase.</param>
        /// <param name="machineSecret">The machine secret.</param>
        /// <returns></returns>
        private static byte[] DeriveKEK(byte[] salt, int iterations, string? passphrase, byte[]? machineSecret)
        {
            using var hmac = new HMACSHA256();

            byte[] pass = string.IsNullOrEmpty(passphrase) ? Array.Empty<byte>() : System.Text.Encoding.UTF8.GetBytes(passphrase);
            byte[] mix = new byte[pass.Length + (machineSecret?.Length ?? 0)];
            Buffer.BlockCopy(pass, 0, mix, 0, pass.Length);
            if (machineSecret is { Length: > 0 })
                Buffer.BlockCopy(machineSecret, 0, mix, pass.Length, machineSecret.Length);

            using var pbkdf2 = new Rfc2898DeriveBytes(mix, salt, iterations, HashAlgorithmName.SHA256);
            var kek = pbkdf2.GetBytes(32);

            Array.Clear(pass, 0, pass.Length);
            Array.Clear(mix, 0, mix.Length);
            return kek;
        }

        /// <summary>Save the list of config items as a crypted file.</summary>
        /// <param name="configFilePath">The path of the config file.</param>
        /// <param name="passphrase">The passphrase.</param>
        /// <param name="machineSecretPath">The path of the machine secret file.</param>
        /// <param name="pbkdf2Iterations">The number of PBKDF2 iterations.</param>
        public void Save(string configFilePath, string? passphrase = null, string? machineSecretPath = null, int pbkdf2Iterations = 300_000)
        {
            /* Version      : 1
             * KDF-Label    : ratCORE-DEK-v1
             * --------------------------------------------
             * Header-Layout:
             * 
             * MAGIC        :  4 bytes = 'RCCC' (ratCORE Crypted Config)
             * VERSION      :  1 byte  = 1
             * FLAGS        :  1 byte  = Bitmask: 0x1=Passphrase only, 0x2=MachineSecret only, 0x3=Passphrase+MachineSecret
             * ITERATIONS   :  4 bytes = PBKDF2-Iterations (int32, e.g. 200_000)
             * SALT         : 16 bytes = for KDF
             * NONCE        : 12 bytes = for AES-GCM
             * CIPHERTEXT   :  x bytes = encrypted JSON-Bytes
             * TAG          : 16 bytes = GCM-Tag
             */

            // plaintext json
            var plaintext = JsonSerializer.SerializeToUtf8Bytes(this, JsonOpts);

            // header fields
            var flags = EncFlags.None;
            if (!string.IsNullOrEmpty(passphrase)) flags |= EncFlags.Passphrase;

            byte[]? machineSecret = null;
            if (machineSecretPath is null) machineSecretPath = GetDefaultSecretPath(configFilePath);
            machineSecret = GetOrCreateMachineSecret(machineSecretPath);
            if (machineSecret.Length > 0) flags |= EncFlags.MachineSecret;

            var salt = RandomBytes(16);
            var nonce = RandomBytes(12);

            // derive KEK (key encryption key) (from passphrase and machine secret)
            var kek = DeriveKEK(salt, pbkdf2Iterations, passphrase, machineSecret);

            // "derive" DEK (data encryption key) from KEK (simple HKDF look alike: HMAC(kek, "DEK"))
            byte[] dek;
            using (var hk = new HMACSHA256(kek))
                dek = hk.ComputeHash(System.Text.Encoding.UTF8.GetBytes(KDFLabel[VERSION - 1]));

            // build header: MAGIC|VERSION|FLAGS|ITERATIONS|SALT|NONCE
            using var header = new MemoryStream();
            header.Write(MAGIC, 0, MAGIC.Length);
            header.WriteByte(VERSION);
            header.WriteByte((byte)flags);
            Span<byte> iterBytes = stackalloc byte[4];
            BinaryPrimitives.WriteInt32LittleEndian(iterBytes, pbkdf2Iterations);
            header.Write(iterBytes);
            header.Write(salt, 0, salt.Length);
            header.Write(nonce, 0, nonce.Length);
            byte[] headerBytes = header.ToArray();

            // encrypt AES-GCM
            var ciphertext = new byte[plaintext.Length];
            var tag = new byte[16];
            using (var gcm = new AesGcm(dek, tagSizeInBytes: 16))
            {
                gcm.Encrypt(nonce, plaintext, ciphertext, tag, associatedData: headerBytes);
            }

            // write file: HEADER|CIPHERTEXT|TAG
            using var fs = new FileStream(configFilePath, FileMode.Create, FileAccess.Write, FileShare.None);
            fs.Write(headerBytes, 0, headerBytes.Length);
            fs.Write(ciphertext, 0, ciphertext.Length);
            fs.Write(tag, 0, tag.Length);
        }

        /// <summary>Load the list of config items from a crypted file.</summary>
        /// <param name="configFilePath">The path of the config file.</param>
        /// <param name="passphrase">The passphrase.</param>
        /// <param name="machineSecretPath">The path of the machine secret file.</param>
        public static CryptedConfig Load(string configFilePath, string? passphrase = null, string? machineSecretPath = null)
        {
            if (!File.Exists(configFilePath)) throw new ConfigFileNotFoundException($"Config file '{configFilePath}' not found!");

            using var fs = new FileStream(configFilePath, FileMode.Open, FileAccess.Read, FileShare.Read);

            // create memory stream for header
            using var header = new MemoryStream();

            // MAGIC
            Span<byte> head = stackalloc byte[4];
            if (fs.Read(head) != 4 || !head.SequenceEqual(MAGIC)) throw new InvalidDataException("Invalid header!");
            header.Write(MAGIC, 0, MAGIC.Length); // header: add MAGIC

            // VERSION
            int v = fs.ReadByte();
            header.WriteByte((byte)v); // header: add VERSION
            if (v == 1)
            {
                /* Version      : 1
                 * KDF-Label    : ratCORE-DEK-v1
                 * --------------------------------------------
                 * Header-Layout:
                 * 
                 * MAGIC        :  4 bytes = 'RCCC' (ratCORE Crypted Config)
                 * VERSION      :  1 byte  = 1
                 * FLAGS        :  1 byte  = Bitmask: 0x1=Passphrase only, 0x2=MachineSecret only, 0x3=Passphrase+MachineSecret
                 * ITERATIONS   :  4 bytes = PBKDF2-Iterations (int32, e.g. 200_000)
                 * SALT         : 16 bytes = for KDF
                 * NONCE        : 12 bytes = for AES-GCM
                 * CIPHERTEXT   :  x bytes = encrypted JSON-Bytes
                 * TAG          : 16 bytes = GCM-Tag
                 */

                // FLAGS
                int f = fs.ReadByte();
                var flags = (EncFlags)f;
                header.WriteByte((byte)f); // header: add FLAGS

                // ITERATIONS
                Span<byte> iterB = stackalloc byte[4];
                if (fs.Read(iterB) != 4) throw new EndOfStreamException();
                int iterations = BinaryPrimitives.ReadInt32LittleEndian(iterB);
                header.Write(iterB); // header: add ITERATIONS

                // SALT and NONCE
                byte[] salt = new byte[16];
                byte[] nonce = new byte[12];
                if (fs.Read(salt) != salt.Length) throw new EndOfStreamException();
                if (fs.Read(nonce) != nonce.Length) throw new EndOfStreamException();
                header.Write(salt, 0, salt.Length); // header: add SALT
                header.Write(nonce, 0, nonce.Length); // header: add NONCE

                // CIPHERTEXT and TAG
                long remain = fs.Length - fs.Position;
                if (remain < 16) throw new EndOfStreamException();
                int ctLen = (int)remain - 16;

                byte[] ciphertext = new byte[ctLen];
                byte[] tag = new byte[16];
                if (fs.Read(ciphertext) != ctLen) throw new EndOfStreamException();
                if (fs.Read(tag) != 16) throw new EndOfStreamException();

                // check flags
                if (flags.HasFlag(EncFlags.MachineSecret) && machineSecretPath is null) machineSecretPath = GetDefaultSecretPath(configFilePath);
                if (!File.Exists(machineSecretPath)) throw new MachineSecretFileNotFoundException($"Machine secret file '{machineSecretPath}' not found!");
                byte[]? machineSecret = flags.HasFlag(EncFlags.MachineSecret) ? GetOrCreateMachineSecret(machineSecretPath!) : null;

                // derive KEK (key encryption key)
                var kek = DeriveKEK(salt, iterations, passphrase, machineSecret);

                // derive DEK (data encryption key)
                byte[] dek;
                using (var hk = new HMACSHA256(kek))
                    dek = hk.ComputeHash(System.Text.Encoding.UTF8.GetBytes(KDFLabel[v - 1]));

                // decrypt
                byte[] plaintext = new byte[ciphertext.Length];
                byte[] headerBytes = header.ToArray();
                try
                {
                    using (var gcm = new AesGcm(dek, tagSizeInBytes: 16))
                        gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: headerBytes);
                }
                catch (CryptographicException ex)
                {
                    // mapping CryptographicException as InvalidDataException
                    throw new InvalidDataException(
                        ex.Message,
                        ex );
                }

                // deserialize JSON
                return JsonSerializer.Deserialize<CryptedConfig>(plaintext, JsonOpts)!;
            }
            else
            {
                throw new NotSupportedException($"Unsupported version '{v}'.");
            }
        }
    }
}

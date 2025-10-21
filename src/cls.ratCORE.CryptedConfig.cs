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
                using (var gcm = new AesGcm(dek, tagSizeInBytes: 16))
                    gcm.Decrypt(nonce, ciphertext, tag, plaintext, associatedData: headerBytes);

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

/*
 * https://creativecommons.org/licenses/by/4.0/
 * 
 * Attribution 4.0 International
 * 
 * =======================================================================
 * 
 * Creative Commons Corporation ("Creative Commons") is not a law firm and
 * does not provide legal services or legal advice. Distribution of
 * Creative Commons public licenses does not create a lawyer-client or
 * other relationship. Creative Commons makes its licenses and related
 * information available on an "as-is" basis. Creative Commons gives no
 * warranties regarding its licenses, any material licensed under their
 * terms and conditions, or any related information. Creative Commons
 * disclaims all liability for damages resulting from their use to the
 * fullest extent possible.
 * 
 * Using Creative Commons Public Licenses
 * 
 * Creative Commons public licenses provide a standard set of terms and
 * conditions that creators and other rights holders may use to share
 * original works of authorship and other material subject to copyright
 * and certain other rights specified in the public license below. The
 * following considerations are for informational purposes only, are not
 * exhaustive, and do not form part of our licenses.
 * 
 *      Considerations for licensors: Our public licenses are
 *      intended for use by those authorized to give the public
 *      permission to use material in ways otherwise restricted by
 *      copyright and certain other rights. Our licenses are
 *      irrevocable. Licensors should read and understand the terms
 *      and conditions of the license they choose before applying it.
 *      Licensors should also secure all rights necessary before
 *      applying our licenses so that the public can reuse the
 *      material as expected. Licensors should clearly mark any
 *      material not subject to the license. This includes other CC-
 *      licensed material, or material used under an exception or
 *      limitation to copyright. More considerations for licensors:
 *     wiki.creativecommons.org/Considerations_for_licensors
 * 
 *      Considerations for the public: By using one of our public
 *      licenses, a licensor grants the public permission to use the
 *      licensed material under specified terms and conditions. If
 *      the licensor's permission is not necessary for any reason--for
 *      example, because of any applicable exception or limitation to
 *      copyright--then that use is not regulated by the license. Our
 *      licenses grant only permissions under copyright and certain
 *      other rights that a licensor has authority to grant. Use of
 *      the licensed material may still be restricted for other
 *      reasons, including because others have copyright or other
 *      rights in the material. A licensor may make special requests,
 *      such as asking that all changes be marked or described.
 *      Although not required by our licenses, you are encouraged to
 *      respect those requests where reasonable. More considerations
 *      for the public:
 *     wiki.creativecommons.org/Considerations_for_licensees
 * 
 * =======================================================================
 * 
 * Creative Commons Attribution 4.0 International Public License
 * 
 * By exercising the Licensed Rights (defined below), You accept and agree
 * to be bound by the terms and conditions of this Creative Commons
 * Attribution 4.0 International Public License ("Public License"). To the
 * extent this Public License may be interpreted as a contract, You are
 * granted the Licensed Rights in consideration of Your acceptance of
 * these terms and conditions, and the Licensor grants You such rights in
 * consideration of benefits the Licensor receives from making the
 * Licensed Material available under these terms and conditions.
 * 
 * 
 * Section 1 -- Definitions.
 * 
 *   a. Adapted Material means material subject to Copyright and Similar
 *      Rights that is derived from or based upon the Licensed Material
 *      and in which the Licensed Material is translated, altered,
 *      arranged, transformed, or otherwise modified in a manner requiring
 *      permission under the Copyright and Similar Rights held by the
 *      Licensor. For purposes of this Public License, where the Licensed
 *      Material is a musical work, performance, or sound recording,
 *      Adapted Material is always produced where the Licensed Material is
 *      synched in timed relation with a moving image.
 * 
 *   b. Adapter's License means the license You apply to Your Copyright
 *      and Similar Rights in Your contributions to Adapted Material in
 *      accordance with the terms and conditions of this Public License.
 * 
 *   c. Copyright and Similar Rights means copyright and/or similar rights
 *      closely related to copyright including, without limitation,
 *      performance, broadcast, sound recording, and Sui Generis Database
 *      Rights, without regard to how the rights are labeled or
 *      categorized. For purposes of this Public License, the rights
 *      specified in Section 2(b)(1)-(2) are not Copyright and Similar
 *      Rights.
 * 
 *   d. Effective Technological Measures means those measures that, in the
 *      absence of proper authority, may not be circumvented under laws
 *      fulfilling obligations under Article 11 of the WIPO Copyright
 *      Treaty adopted on December 20, 1996, and/or similar international
 *      agreements.
 * 
 *   e. Exceptions and Limitations means fair use, fair dealing, and/or
 *      any other exception or limitation to Copyright and Similar Rights
 *      that applies to Your use of the Licensed Material.
 * 
 *   f. Licensed Material means the artistic or literary work, database,
 *      or other material to which the Licensor applied this Public
 *      License.
 * 
 *   g. Licensed Rights means the rights granted to You subject to the
 *      terms and conditions of this Public License, which are limited to
 *      all Copyright and Similar Rights that apply to Your use of the
 *      Licensed Material and that the Licensor has authority to license.
 * 
 *   h. Licensor means the individual(s) or entity(ies) granting rights
 *      under this Public License.
 * 
 *   i. Share means to provide material to the public by any means or
 *      process that requires permission under the Licensed Rights, such
 *      as reproduction, public display, public performance, distribution,
 *      dissemination, communication, or importation, and to make material
 *      available to the public including in ways that members of the
 *      public may access the material from a place and at a time
 *      individually chosen by them.
 * 
 *   j. Sui Generis Database Rights means rights other than copyright
 *      resulting from Directive 96/9/EC of the European Parliament and of
 *      the Council of 11 March 1996 on the legal protection of databases,
 *      as amended and/or succeeded, as well as other essentially
 *      equivalent rights anywhere in the world.
 * 
 *   k. You means the individual or entity exercising the Licensed Rights
 *      under this Public License. Your has a corresponding meaning.
 * 
 * 
 * Section 2 -- Scope.
 * 
 *   a. License grant.
 * 
 *        1. Subject to the terms and conditions of this Public License,
 *           the Licensor hereby grants You a worldwide, royalty-free,
 *           non-sublicensable, non-exclusive, irrevocable license to
 *           exercise the Licensed Rights in the Licensed Material to:
 * 
 *             a. reproduce and Share the Licensed Material, in whole or
 *                in part; and
 * 
 *             b. produce, reproduce, and Share Adapted Material.
 * 
 *        2. Exceptions and Limitations. For the avoidance of doubt, where
 *           Exceptions and Limitations apply to Your use, this Public
 *           License does not apply, and You do not need to comply with
 *           its terms and conditions.
 * 
 *        3. Term. The term of this Public License is specified in Section
 *           6(a).
 * 
 *        4. Media and formats; technical modifications allowed. The
 *           Licensor authorizes You to exercise the Licensed Rights in
 *           all media and formats whether now known or hereafter created,
 *           and to make technical modifications necessary to do so. The
 *           Licensor waives and/or agrees not to assert any right or
 *           authority to forbid You from making technical modifications
 *           necessary to exercise the Licensed Rights, including
 *           technical modifications necessary to circumvent Effective
 *           Technological Measures. For purposes of this Public License,
 *           simply making modifications authorized by this Section 2(a)
 *           (4) never produces Adapted Material.
 * 
 *        5. Downstream recipients.
 * 
 *             a. Offer from the Licensor -- Licensed Material. Every
 *                recipient of the Licensed Material automatically
 *                receives an offer from the Licensor to exercise the
 *                Licensed Rights under the terms and conditions of this
 *                Public License.
 * 
 *             b. No downstream restrictions. You may not offer or impose
 *                any additional or different terms or conditions on, or
 *                apply any Effective Technological Measures to, the
 *                Licensed Material if doing so restricts exercise of the
 *                Licensed Rights by any recipient of the Licensed
 *                Material.
 * 
 *        6. No endorsement. Nothing in this Public License constitutes or
 *           may be construed as permission to assert or imply that You
 *           are, or that Your use of the Licensed Material is, connected
 *           with, or sponsored, endorsed, or granted official status by,
 *           the Licensor or others designated to receive attribution as
 *           provided in Section 3(a)(1)(A)(i).
 * 
 *   b. Other rights.
 * 
 *        1. Moral rights, such as the right of integrity, are not
 *           licensed under this Public License, nor are publicity,
 *           privacy, and/or other similar personality rights; however, to
 *           the extent possible, the Licensor waives and/or agrees not to
 *           assert any such rights held by the Licensor to the limited
 *           extent necessary to allow You to exercise the Licensed
 *           Rights, but not otherwise.
 * 
 *        2. Patent and trademark rights are not licensed under this
 *           Public License.
 * 
 *        3. To the extent possible, the Licensor waives any right to
 *           collect royalties from You for the exercise of the Licensed
 *           Rights, whether directly or through a collecting society
 *           under any voluntary or waivable statutory or compulsory
 *           licensing scheme. In all other cases the Licensor expressly
 *           reserves any right to collect such royalties.
 * 
 * 
 * Section 3 -- License Conditions.
 * 
 * Your exercise of the Licensed Rights is expressly made subject to the
 * following conditions.
 * 
 *   a. Attribution.
 * 
 *        1. If You Share the Licensed Material (including in modified
 *           form), You must:
 * 
 *             a. retain the following if it is supplied by the Licensor
 *                with the Licensed Material:
 * 
 *                  i. identification of the creator(s) of the Licensed
 *                     Material and any others designated to receive
 *                     attribution, in any reasonable manner requested by
 *                     the Licensor (including by pseudonym if
 *                     designated);
 * 
 *                 ii. a copyright notice;
 * 
 *                iii. a notice that refers to this Public License;
 * 
 *                 iv. a notice that refers to the disclaimer of
 *                     warranties;
 * 
 *                  v. a URI or hyperlink to the Licensed Material to the
 *                     extent reasonably practicable;
 * 
 *             b. indicate if You modified the Licensed Material and
 *                retain an indication of any previous modifications; and
 * 
 *             c. indicate the Licensed Material is licensed under this
 *                Public License, and include the text of, or the URI or
 *                hyperlink to, this Public License.
 * 
 *        2. You may satisfy the conditions in Section 3(a)(1) in any
 *           reasonable manner based on the medium, means, and context in
 *           which You Share the Licensed Material. For example, it may be
 *           reasonable to satisfy the conditions by providing a URI or
 *           hyperlink to a resource that includes the required
 *           information.
 * 
 *        3. If requested by the Licensor, You must remove any of the
 *           information required by Section 3(a)(1)(A) to the extent
 *           reasonably practicable.
 * 
 *        4. If You Share Adapted Material You produce, the Adapter's
 *           License You apply must not prevent recipients of the Adapted
 *           Material from complying with this Public License.
 * 
 * 
 * Section 4 -- Sui Generis Database Rights.
 * 
 * Where the Licensed Rights include Sui Generis Database Rights that
 * apply to Your use of the Licensed Material:
 * 
 *   a. for the avoidance of doubt, Section 2(a)(1) grants You the right
 *      to extract, reuse, reproduce, and Share all or a substantial
 *      portion of the contents of the database;
 * 
 *   b. if You include all or a substantial portion of the database
 *      contents in a database in which You have Sui Generis Database
 *      Rights, then the database in which You have Sui Generis Database
 *      Rights (but not its individual contents) is Adapted Material; and
 * 
 *   c. You must comply with the conditions in Section 3(a) if You Share
 *      all or a substantial portion of the contents of the database.
 * 
 * For the avoidance of doubt, this Section 4 supplements and does not
 * replace Your obligations under this Public License where the Licensed
 * Rights include other Copyright and Similar Rights.
 * 
 * 
 * Section 5 -- Disclaimer of Warranties and Limitation of Liability.
 * 
 *   a. UNLESS OTHERWISE SEPARATELY UNDERTAKEN BY THE LICENSOR, TO THE
 *      EXTENT POSSIBLE, THE LICENSOR OFFERS THE LICENSED MATERIAL AS-IS
 *      AND AS-AVAILABLE, AND MAKES NO REPRESENTATIONS OR WARRANTIES OF
 *      ANY KIND CONCERNING THE LICENSED MATERIAL, WHETHER EXPRESS,
 *      IMPLIED, STATUTORY, OR OTHER. THIS INCLUDES, WITHOUT LIMITATION,
 *      WARRANTIES OF TITLE, MERCHANTABILITY, FITNESS FOR A PARTICULAR
 *      PURPOSE, NON-INFRINGEMENT, ABSENCE OF LATENT OR OTHER DEFECTS,
 *      ACCURACY, OR THE PRESENCE OR ABSENCE OF ERRORS, WHETHER OR NOT
 *      KNOWN OR DISCOVERABLE. WHERE DISCLAIMERS OF WARRANTIES ARE NOT
 *      ALLOWED IN FULL OR IN PART, THIS DISCLAIMER MAY NOT APPLY TO YOU.
 * 
 *   b. TO THE EXTENT POSSIBLE, IN NO EVENT WILL THE LICENSOR BE LIABLE
 *      TO YOU ON ANY LEGAL THEORY (INCLUDING, WITHOUT LIMITATION,
 *      NEGLIGENCE) OR OTHERWISE FOR ANY DIRECT, SPECIAL, INDIRECT,
 *      INCIDENTAL, CONSEQUENTIAL, PUNITIVE, EXEMPLARY, OR OTHER LOSSES,
 *      COSTS, EXPENSES, OR DAMAGES ARISING OUT OF THIS PUBLIC LICENSE OR
 *      USE OF THE LICENSED MATERIAL, EVEN IF THE LICENSOR HAS BEEN
 *      ADVISED OF THE POSSIBILITY OF SUCH LOSSES, COSTS, EXPENSES, OR
 *      DAMAGES. WHERE A LIMITATION OF LIABILITY IS NOT ALLOWED IN FULL OR
 *      IN PART, THIS LIMITATION MAY NOT APPLY TO YOU.
 * 
 *   c. The disclaimer of warranties and limitation of liability provided
 *      above shall be interpreted in a manner that, to the extent
 *      possible, most closely approximates an absolute disclaimer and
 *      waiver of all liability.
 * 
 * 
 * Section 6 -- Term and Termination.
 * 
 *   a. This Public License applies for the term of the Copyright and
 *      Similar Rights licensed here. However, if You fail to comply with
 *      this Public License, then Your rights under this Public License
 *      terminate automatically.
 * 
 *   b. Where Your right to use the Licensed Material has terminated under
 *      Section 6(a), it reinstates:
 * 
 *        1. automatically as of the date the violation is cured, provided
 *           it is cured within 30 days of Your discovery of the
 *           violation; or
 * 
 *        2. upon express reinstatement by the Licensor.
 * 
 *      For the avoidance of doubt, this Section 6(b) does not affect any
 *      right the Licensor may have to seek remedies for Your violations
 *      of this Public License.
 * 
 *   c. For the avoidance of doubt, the Licensor may also offer the
 *      Licensed Material under separate terms or conditions or stop
 *      distributing the Licensed Material at any time; however, doing so
 *      will not terminate this Public License.
 * 
 *   d. Sections 1, 5, 6, 7, and 8 survive termination of this Public
 *      License.
 * 
 * 
 * Section 7 -- Other Terms and Conditions.
 * 
 *   a. The Licensor shall not be bound by any additional or different
 *      terms or conditions communicated by You unless expressly agreed.
 * 
 *   b. Any arrangements, understandings, or agreements regarding the
 *      Licensed Material not stated herein are separate from and
 *      independent of the terms and conditions of this Public License.
 * 
 * 
 * Section 8 -- Interpretation.
 * 
 *   a. For the avoidance of doubt, this Public License does not, and
 *      shall not be interpreted to, reduce, limit, restrict, or impose
 *      conditions on any use of the Licensed Material that could lawfully
 *      be made without permission under this Public License.
 * 
 *   b. To the extent possible, if any provision of this Public License is
 *      deemed unenforceable, it shall be automatically reformed to the
 *      minimum extent necessary to make it enforceable. If the provision
 *      cannot be reformed, it shall be severed from this Public License
 *      without affecting the enforceability of the remaining terms and
 *      conditions.
 * 
 *   c. No term or condition of this Public License will be waived and no
 *      failure to comply consented to unless expressly agreed to by the
 *      Licensor.
 * 
 *   d. Nothing in this Public License constitutes or may be interpreted
 *      as a limitation upon, or waiver of, any privileges and immunities
 *      that apply to the Licensor or You, including from the legal
 *      processes of any jurisdiction or authority.
 * 
 * 
 * =======================================================================
 * 
 * Creative Commons is not a party to its public
 * licenses. Notwithstanding, Creative Commons may elect to apply one of
 * its public licenses to material it publishes and in those instances
 * will be considered the “Licensor.” The text of the Creative Commons
 * public licenses is dedicated to the public domain under the CC0 Public
 * Domain Dedication. Except for the limited purpose of indicating that
 * material is shared under a Creative Commons public license or as
 * otherwise permitted by the Creative Commons policies published at
 * creativecommons.org/policies, Creative Commons does not authorize the
 * use of the trademark "Creative Commons" or any other trademark or logo
 * of Creative Commons without its prior written consent including,
 * without limitation, in connection with any unauthorized modifications
 * to any of its public licenses or any other arrangements,
 * understandings, or agreements concerning use of licensed material. For
 * the avoidance of doubt, this paragraph does not form part of the
 * public licenses.
 * 
 * Creative Commons may be contacted at creativecommons.org.
 * 
 */
using System;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using VisualScript.Icons;

namespace VisualScript.Runtime.AES256
{
    [Title("AES with HMAC")]
    [Category("AES with HMAC")]

    [Image(typeof(IconLockSolid), ColorTheme.Type.Yellow, typeof(BadgeShield))]
    [Description("Encrypts with AES-256 and authenticates with HMAC-SHA256")]

    [Note("Tampered or corrupt data is rejected when loading")]
    [Note("Keys are stretched with PBKDF2 from a random salt that travels with each payload")]
    [Note("Bind the Secret to a variable, a server response or a custom Signal to keep it out of the build")]
    [Note("Set the Iterations value between 10k and 1 million")]

    [Serializable]
    public class EncryptionAes256 : EncryptionBase
    {
        private const byte VERSION = 1;

        private const int VERSION_SIZE = 1;
        private const int ITERATIONS_SIZE = 4;
        private const int SALT_SIZE = 16;
        private const int IV_SIZE = 16;
        private const int HMAC_SIZE = 32;

        private const int KEY_SIZE = 32;
        private const int BLOCK_SIZE = 16;

        private const int OFFSET_VERSION = 0;
        private const int OFFSET_ITERATIONS = OFFSET_VERSION + VERSION_SIZE;
        private const int OFFSET_SALT = OFFSET_ITERATIONS + ITERATIONS_SIZE;
        private const int OFFSET_IV = OFFSET_SALT + SALT_SIZE;
        private const int OFFSET_CIPHER = OFFSET_IV + IV_SIZE;

        public const int MIN_ITERATIONS = 10_000;
        public const int MAX_ITERATIONS = 1_000_000;

        private const int DEFAULT_ITERATIONS = 10_0000;

        private const string ERR_DECRYPT = "Could not decrypt save data: {0}";
        private const string ERR_NO_SECRET = "The AES encryption Secret is empty";

        private static readonly byte[] INFO_CIPHER = Encoding.ASCII.GetBytes("visualscript:aes256-cipher");
        private static readonly byte[] INFO_SIGNATURE = Encoding.ASCII.GetBytes("visualscript:aes256-signature");

        // EXPOSED MEMBERS: -----------------------------------------------------------------------

        [SerializeField] private GetString m_Secret = new GetString("6b6169");
        [SerializeField] private int m_Iterations = DEFAULT_ITERATIONS;

        // MEMBERS: -------------------------------------------------------------------------------

        [NonSerialized] private string m_CachedSecret;
        [NonSerialized] private byte[] m_CachedSalt;
        [NonSerialized] private int m_CachedIterations;

        [NonSerialized] private byte[] m_CipherKey;
        [NonSerialized] private byte[] m_SignatureKey;

        // PROPERTIES: ----------------------------------------------------------------------------

        private int Iterations => Mathf.Clamp(this.m_Iterations, MIN_ITERATIONS, MAX_ITERATIONS);

        // PUBLIC METHODS: ------------------------------------------------------------------------

        public override string Encrypt(string input)
        {
            if (input == null) return null;

            string secret = this.GetSecret();
            int iterations = this.Iterations;

            this.RequireKeys(secret, this.RequireSalt(secret, iterations), iterations);

            byte[] plain = Encoding.UTF8.GetBytes(input);

            using Aes aes = CreateAes();
            aes.Key = this.m_CipherKey;
            aes.GenerateIV();

            byte[] cipher;
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                cipher = encryptor.TransformFinalBlock(plain, 0, plain.Length);
            }

            Array.Clear(plain, 0, plain.Length);

            byte[] payload = new byte[OFFSET_CIPHER + cipher.Length + HMAC_SIZE];

            payload[OFFSET_VERSION] = VERSION;
            WriteInt32(payload, OFFSET_ITERATIONS, iterations);

            Buffer.BlockCopy(this.m_CachedSalt, 0, payload, OFFSET_SALT, SALT_SIZE);
            Buffer.BlockCopy(aes.IV, 0, payload, OFFSET_IV, IV_SIZE);
            Buffer.BlockCopy(cipher, 0, payload, OFFSET_CIPHER, cipher.Length);

            int signedLength = payload.Length - HMAC_SIZE;

            using (HMACSHA256 hmac = new HMACSHA256(this.m_SignatureKey))
            {
                byte[] signature = hmac.ComputeHash(payload, 0, signedLength);
                Buffer.BlockCopy(signature, 0, payload, signedLength, HMAC_SIZE);
            }

            return Convert.ToBase64String(payload);
        }

        public override string Decrypt(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;

            byte[] payload;

            try
            {
                payload = Convert.FromBase64String(input);
            }
            catch (FormatException)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "Payload is not valid Base64");
                return string.Empty;
            }

            if (payload.Length < OFFSET_CIPHER + BLOCK_SIZE + HMAC_SIZE)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "Payload is too short");
                return string.Empty;
            }

            if (payload[OFFSET_VERSION] != VERSION)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, $"Unknown version format: {payload[OFFSET_VERSION]}");
                return string.Empty;
            }

            int iterations = ReadInt32(payload, OFFSET_ITERATIONS);

            if (iterations < MIN_ITERATIONS || iterations > MAX_ITERATIONS)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "Payload has unsupported amount of iterations");
                return string.Empty;
            }

            byte[] salt = new byte[SALT_SIZE];
            Buffer.BlockCopy(payload, OFFSET_SALT, salt, 0, SALT_SIZE);

            this.RequireKeys(this.GetSecret(), salt, iterations);

            int signedLength = payload.Length - HMAC_SIZE;

            using (HMACSHA256 hmac = new HMACSHA256(this.m_SignatureKey))
            {
                byte[] signature = hmac.ComputeHash(payload, 0, signedLength);
                if (!CheckSignatureMatch(signature, payload, signedLength))
                {
                    Debug.LogWarningFormat(ERR_DECRYPT, "Signature does not match. Wrong secret or tampered data");
                    return string.Empty;
                }
            }

            int cipherLength = signedLength - OFFSET_CIPHER;

            if (cipherLength <= 0 || cipherLength % BLOCK_SIZE != 0)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "Payload length is not a whole number of blocks");
                return string.Empty;
            }

            byte[] iv = new byte[IV_SIZE];
            Buffer.BlockCopy(payload, OFFSET_IV, iv, 0, IV_SIZE);

            using Aes aes = CreateAes();
            aes.Key = this.m_CipherKey;
            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] plain = decryptor.TransformFinalBlock(payload, OFFSET_CIPHER, cipherLength);

                string result = Encoding.UTF8.GetString(plain);
                Array.Clear(plain, 0, plain.Length);

                return result;
            }
            catch (CryptographicException exception)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, exception.Message);
                return string.Empty;
            }
        }

        // PRIVATE METHODS: -----------------------------------------------------------------------

        private string GetSecret()
        {
            if (this.m_Secret == null) return string.Empty;

            using Args args = Args.Get();
            return this.m_Secret.Get(args) ?? string.Empty;
        }

        private byte[] RequireSalt(string secret, int iterations)
        {
            bool isCached = this.m_CipherKey != null &&
                            this.m_CachedIterations == iterations &&
                            this.m_CachedSecret == secret;

            return isCached ? this.m_CachedSalt : CreateRandomBytes(SALT_SIZE);
        }

        private void RequireKeys(string secret, byte[] salt, int iterations)
        {
            if (this.m_CipherKey != null &&
                this.m_CachedIterations == iterations &&
                this.m_CachedSecret == secret &&
                CheckSaltMatch(this.m_CachedSalt, salt))
            {
                return;
            }

            if (string.IsNullOrEmpty(secret)) Debug.LogWarning(ERR_NO_SECRET);

            byte[] master;

            using (Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(
                       secret, salt, iterations, HashAlgorithmName.SHA256))
            {
                master = derive.GetBytes(KEY_SIZE);
            }

            this.m_CipherKey = Expand(master, INFO_CIPHER);
            this.m_SignatureKey = Expand(master, INFO_SIGNATURE);

            Array.Clear(master, 0, master.Length);

            this.m_CachedSecret = secret;
            this.m_CachedSalt = salt;
            this.m_CachedIterations = iterations;
        }

        private static Aes CreateAes()
        {
            AesManaged aes = new AesManaged
            {
                Mode = CipherMode.CBC,
                Padding = PaddingMode.PKCS7
            };

            return aes;
        }

        private static byte[] Expand(byte[] master, byte[] info)
        {
            using HMACSHA256 hmac = new HMACSHA256(master);
            return hmac.ComputeHash(info);
        }

        private static byte[] CreateRandomBytes(int size)
        {
            byte[] bytes = new byte[size];

            using RandomNumberGenerator random = RandomNumberGenerator.Create();
            random.GetBytes(bytes);

            return bytes;
        }

        private static void WriteInt32(byte[] payload, int offset, int value)
        {
            payload[offset] = (byte) (value >> 24);
            payload[offset + 1] = (byte) (value >> 16);
            payload[offset + 2] = (byte) (value >> 8);
            payload[offset + 3] = (byte) value;
        }

        private static int ReadInt32(byte[] payload, int offset)
        {
            return (payload[offset] << 24) |
                   (payload[offset + 1] << 16) |
                   (payload[offset + 2] << 8) |
                   payload[offset + 3];
        }

        private static bool CheckSignatureMatch(byte[] signature, byte[] payload, int offset)
        {
            int difference = 0;
            for (int i = 0; i < HMAC_SIZE; ++i)
            {
                difference |= signature[i] ^ payload[offset + i];
            }

            return difference == 0;
        }

        private static bool CheckSaltMatch(byte[] a, byte[] b)
        {
            if (a == null || b == null || a.Length != b.Length) return false;

            for (int i = 0; i < a.Length; ++i)
            {
                if (a[i] != b[i]) return false;
            }

            return true;
        }
    }
}
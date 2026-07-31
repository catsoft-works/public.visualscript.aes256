using System;
using System.Security.Cryptography;
using System.Text;
using UnityEngine;
using VisualScript.Icons;

namespace VisualScript.Runtime.AES256
{
    [Title("AES with HMAC")]
    [Category("AES with HMAC")]

    [Image(typeof(IconShieldSolid), ColorTheme.Type.Green)]
    [Description("Encrypts values with AES-256 and authenticates them with HMAC-SHA256")]

    [Note("Tampered or corrupt data is rejected on load")]
    [Note("HMAC is used to ensure the data integrity and authenticity")]

    [Serializable]
    public class EncryptionAes256 : EncryptionBase
    {
        private const int KEY_SIZE = 32;
        private const int IV_SIZE = 16;
        private const int HMAC_SIZE = 32;

        private const int PBKDF2_ITERATIONS = 10000;

        private const string ERR_DECRYPT = "Could not decrypt save data: {0}";

        private static readonly byte[] SALT =
        {
            0x56, 0x69, 0x73, 0x75, 0x61, 0x6C, 0x53, 0x63,
            0x72, 0x69, 0x70, 0x74, 0x2E, 0x41, 0x65, 0x73
        };

        // EXPOSED MEMBERS: -----------------------------------------------------------------------

        [SerializeField] private string m_Secret = "Fidelius";

        // MEMBERS: -------------------------------------------------------------------------------

        [NonSerialized] private string m_CachedSecret;

        [NonSerialized] private byte[] m_AesKey;
        [NonSerialized] private byte[] m_HmacKey;

        // PUBLIC METHODS: ------------------------------------------------------------------------

        public override string Encrypt(string input)
        {
            if (input == null) return null;
            this.RequireKeys();

            byte[] plain = Encoding.UTF8.GetBytes(input);

            using Aes aes = Aes.Create();
            aes.Key = this.m_AesKey;
            aes.GenerateIV();

            byte[] cipher;
            using (ICryptoTransform encryptor = aes.CreateEncryptor())
            {
                cipher = encryptor.TransformFinalBlock(plain, 0, plain.Length);
            }

            byte[] payload = new byte[HMAC_SIZE + IV_SIZE + cipher.Length];
            Buffer.BlockCopy(aes.IV, 0, payload, HMAC_SIZE, IV_SIZE);
            Buffer.BlockCopy(cipher, 0, payload, HMAC_SIZE + IV_SIZE, cipher.Length);

            using (HMACSHA256 hmac = new HMACSHA256(this.m_HmacKey))
            {
                byte[] signature = hmac.ComputeHash(payload, HMAC_SIZE, payload.Length - HMAC_SIZE);
                Buffer.BlockCopy(signature, 0, payload, 0, HMAC_SIZE);
            }

            return Convert.ToBase64String(payload);
        }

        public override string Decrypt(string input)
        {
            if (string.IsNullOrEmpty(input)) return input;
            this.RequireKeys();

            byte[] payload;

            try
            {
                payload = Convert.FromBase64String(input);
            }
            catch (FormatException)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "the payload is not valid Base64");
                return string.Empty;
            }

            if (payload.Length < HMAC_SIZE + IV_SIZE)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, "the payload is too short");
                return string.Empty;
            }

            using (HMACSHA256 hmac = new HMACSHA256(this.m_HmacKey))
            {
                byte[] signature = hmac.ComputeHash(payload, HMAC_SIZE, payload.Length - HMAC_SIZE);
                if (!CheckSignatureMatch(signature, payload))
                {
                    Debug.LogWarningFormat(ERR_DECRYPT, "the signature does not match. Wrong secret or tampered data");
                    return string.Empty;
                }
            }

            byte[] iv = new byte[IV_SIZE];
            Buffer.BlockCopy(payload, HMAC_SIZE, iv, 0, IV_SIZE);

            using Aes aes = Aes.Create();
            aes.Key = this.m_AesKey;
            aes.IV = iv;

            try
            {
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                byte[] plain = decryptor.TransformFinalBlock(
                    payload,
                    HMAC_SIZE + IV_SIZE,
                    payload.Length - HMAC_SIZE - IV_SIZE
                );

                return Encoding.UTF8.GetString(plain);
            }
            catch (CryptographicException exception)
            {
                Debug.LogWarningFormat(ERR_DECRYPT, exception.Message);
                return string.Empty;
            }
        }

        // PRIVATE METHODS: -----------------------------------------------------------------------

        private void RequireKeys()
        {
            if (this.m_AesKey != null && this.m_CachedSecret == this.m_Secret) return;

            using Rfc2898DeriveBytes derive = new Rfc2898DeriveBytes(
                this.m_Secret ?? string.Empty,
                SALT,
                PBKDF2_ITERATIONS,
                HashAlgorithmName.SHA256
            );

            this.m_AesKey = derive.GetBytes(KEY_SIZE);
            this.m_HmacKey = derive.GetBytes(KEY_SIZE);
            this.m_CachedSecret = this.m_Secret;
        }

        private static bool CheckSignatureMatch(byte[] signature, byte[] payload)
        {
            int difference = 0;
            for (int i = 0; i < HMAC_SIZE; ++i)
            {
                difference |= signature[i] ^ payload[i];
            }

            return difference == 0;
        }
    }
}
using Bink.Hashing;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace Bink.Encryption.Symmetric.AES
{
    public class BinkSym
    {
        BinkMD5 BinkMD5 = new BinkMD5();
        public string GenerateKey() => BinkMD5.Hash(Guid.NewGuid().ToString());
        public byte[] Encrypt(byte[] data, string key)
        {
            byte[] array;
            using (var aes = Aes.Create())
            {
                aes.Key = BinkMD5.HashBytes(key);
                aes.IV = IVCreate();
                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                {
                    using (MemoryStream memoryStream = new MemoryStream())
                    {
                        using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                        {
                            cryptoStream.Write(data, 0, data.Length);
                            cryptoStream.FlushFinalBlock();
                            memoryStream.Write(aes.IV, 0, aes.IV.Length);
                            array = memoryStream.ToArray();
                        }
                    }
                }
            }
            return array;
        }
        public byte[] Decrypt(byte[] buffer, string key)
        {
            using (var aes = Aes.Create())
            {
                aes.Key = BinkMD5.HashBytes(key);
                aes.IV = buffer.Skip(buffer.Length - 16).Take(16).ToArray();
                using (var memoryStream = new MemoryStream(buffer.Take(buffer.Length - 16).ToArray()))
                {
                    using (var decryptor = aes.CreateDecryptor(aes.Key, aes.IV))
                    {
                        using (var cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                        {
                            using (var streamReader = new MemoryStream())
                            {
                                cryptoStream.CopyTo(streamReader);
                                return streamReader.ToArray();
                            }
                        }
                    }
                }
            }
        }
        int IVLength = 16;
        public byte[] IVCreate()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] iv = new byte[IVLength];
                rng.GetBytes(iv);
                return iv;
            }
        }
        public byte[] Encrypt(string plainText, string key)
        {
            return Encrypt(Encoding.UTF8.GetBytes(plainText), key);
        }
        public byte[] Decrypt(string encText, string key)
        {
            return Decrypt(Convert.FromBase64String(encText), key);
        }
        public string EncryptToString(string plainText, string key)
        {
            return Convert.ToBase64String(Encrypt(Encoding.UTF8.GetBytes(plainText), key));
        }
        public string EncryptToString(byte[] plainText, string key)
        {
            return Convert.ToBase64String(Encrypt(plainText, key));
        }
        public string DecryptToString(string encText, string key)
        {
            return Encoding.UTF8.GetString(Decrypt(Convert.FromBase64String(encText), key));
        }
        public string DecryptToString(byte[] encBytes, string key)
        {
            return Encoding.UTF8.GetString(Decrypt(encBytes, key));
        }
    }
}

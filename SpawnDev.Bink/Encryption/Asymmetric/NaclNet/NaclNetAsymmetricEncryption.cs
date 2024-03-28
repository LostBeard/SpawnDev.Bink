using Bink.Hashing;
using NaCl;
using System;
using System.Collections.Generic;
using System.Linq;
//using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;

namespace Bink.Encryption.Asymmetric.NaclNet
{
    // Typical encryption usage example
    //• Generate a random AES key.
    //• Use the AES key to encrypt the packet.
    //• Hash the encrypted packet using SHA-256.
    //• Read Alice’s RSA secret key from “wire format.”
    //• Use Alice’s RSA secret key to sign the hash.
    //• Read Bob’s RSA public key from wire format.
    //• Use Bob’s public key to encrypt the AES key, hash, and signature.
    //• Convert the encrypted key, hash, and signature to wire format.
    //• Concatenate with the encrypted packet.
    // https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    
    // https://github.com/somdoron/NaCl.net
    public class NaclNetAsymmetricEncryption : AsymmetricBase
    {
        public const string AsymType = "NACL";

        // might not be the right way, doing it for now until corrected
        // using shared keypair allows us to sign/verify and encrypt/decrypt like our AES does
        private static string sharedPrivateKey = "qKy3fo7m/O0bEk6DbD0Mqltwna2HMvpnHXsqnBovkQA=";
        private static string sharedPublicKey = "Fudx0AuU4moZYB8S3o418H/p6vUt1NIFOfsSGyHTmFk=";
        static byte[] sharedPrivateKeyBytes = Convert.FromBase64String(sharedPrivateKey);
        static byte[] sharedPublicKeyBytes = Convert.FromBase64String(sharedPublicKey);
        BinkSHA1 BinkSHA1 = new BinkSHA1();

        public override int PrivateKeySize { get; }
        public override int PublicKeySize { get; }

        public NaclNetAsymmetricEncryption()
        {
            KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
            PrivateKeySize = privateKey.Length;
            PublicKeySize = publicKey.Length;
        }

        public override string KeyToString(byte[] key) => Convert.ToBase64String(key);
        public override byte[] KeyToBytes(string key) => Convert.FromBase64String(key);
        public override string TokenToString(byte[] token) => Convert.ToBase64String(token);
        public override byte[] TokenToBytes(string token) => Convert.FromBase64String(token);

        public byte[] NonceCreate()
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] nonce = new byte[Curve25519XSalsa20Poly1305.NonceLength];
                rng.GetBytes(nonce);
                return nonce;
            }
        }

        #region KeyPair
        public override bool KeyPairFromString(string keyPairString, out byte[] privateKey, out byte[] publicKey)
        {
            privateKey = default(byte[]);
            publicKey = default(byte[]);
            if (!KeyPairFromString(keyPairString, out string privateKeyStr, out string publicKeyStr)) return false;
            (privateKey, publicKey) = (Convert.FromBase64String(privateKeyStr), Convert.FromBase64String(publicKeyStr));
            return true;
        }

        public override bool KeyPairFromString(string keyPairString, out string privateKey, out string publicKey)
        {
            privateKey = "";
            publicKey = "";
            if (string.IsNullOrEmpty(keyPairString) || !keyPairString.Contains("|")) return false;
            var p = keyPairString.Split('|');
            (privateKey, publicKey) = (p[0], p[1]);
            return true;
        }

        public override string KeyPairToString(string privateKey, string publicKey)
        {
            return $"{privateKey}|{publicKey}";
        }

        public override string KeyPairToString(byte[] privateKey, byte[] publicKey)
        {
            return KeyPairToString(KeyToString(privateKey), KeyToString(publicKey));
        }

        public override void KeyPairCreate(out string privateKey, out string publicKey)
        {
            Curve25519XSalsa20Poly1305.KeyPair(out var privateKeyBytes, out var publicKeyBytes);
            privateKey = KeyToString(privateKeyBytes);
            publicKey = KeyToString(publicKeyBytes);
        }

        public override void KeyPairCreate(out byte[] privateKey, out byte[] publicKey)
        {
            Curve25519XSalsa20Poly1305.KeyPair(out privateKey, out publicKey);
        }
        #endregion

        public override byte[] Decrypt(byte[] encryptedMessage, byte[] recipientPrivateKey, byte[] senderPublicKey)
        {
            using (var receiveBox = new Curve25519XSalsa20Poly1305(recipientPrivateKey, senderPublicKey))
            {
                byte[] nonce = new byte[Curve25519XSalsa20Poly1305.NonceLength];
                Buffer.BlockCopy(encryptedMessage, 0, nonce, 0, nonce.Length);
                var cipher = new byte[encryptedMessage.Length - nonce.Length];
                Buffer.BlockCopy(encryptedMessage, nonce.Length, cipher, 0, cipher.Length);
                byte[] message = new byte[cipher.Length - Curve25519XSalsa20Poly1305.TagLength];
                bool isVerified = receiveBox.TryDecrypt(message, cipher, nonce);
                if (!isVerified) throw new Exception("Decryption failed");
                return message;
            }
        }
        public override byte[] Decrypt(byte[] encryptedMessage, byte[] recipientPrivateKey)
        {
            return Decrypt(encryptedMessage, recipientPrivateKey, sharedPublicKeyBytes);
        }
        public override byte[] Decrypt(byte[] encryptedMessage, string recipientPrivateKey)
        {
            return Decrypt(encryptedMessage, KeyToBytes(recipientPrivateKey));
        }
        public override byte[] Decrypt(byte[] encryptedMessage, string recipientPrivateKey, string senderPublicKey)
        {
            return Decrypt(encryptedMessage, KeyToBytes(recipientPrivateKey), KeyToBytes(senderPublicKey));
        }
        public override byte[] Encrypt(byte[] message, byte[] recipientPublicKey, byte[] senderPrivateKey)
        {
            using (var sendBox = new Curve25519XSalsa20Poly1305(senderPrivateKey, recipientPublicKey))
            {
                // Generating random nonce
                byte[] nonce = NonceCreate();
                // Prepare the buffer for the ciphertext, must be message length and extra 16 bytes for the authentication tag
                byte[] cipher = new byte[message.Length + Curve25519XSalsa20Poly1305.TagLength];
                // Encrypting using alice box
                sendBox.Encrypt(cipher, message, nonce);
                var ret = nonce.Concat(cipher).ToArray();
                return ret;
            }
        }
        public override byte[] Encrypt(byte[] message, string recipientPublicKey, string senderPrivateKey)
        {
            return Encrypt(message, KeyToBytes(recipientPublicKey), KeyToBytes(senderPrivateKey));
        }
        public override byte[] Encrypt(byte[] message, string recipientPublicKey)
        {
            return Encrypt(message, KeyToBytes(recipientPublicKey));
        }
        public override byte[] Encrypt(byte[] message, byte[] recipientPublicKey)
        {
            return Encrypt(message, recipientPublicKey, sharedPrivateKeyBytes);
        }

        //public byte[] GenerateKeyPair()
        //{
        //    var key = new byte[32];
        //    RandomNumberGenerator.Create().GetBytes(key);

        //    using (var rng = RandomNumberGenerator.Create())
        //    {

        //        Curve25519XSalsa20Poly1305.KeyPair(out var aliceSecretKey, out var alicePublicKey);
        //        var aliceSecretKeyStr = Convert.ToBase64String(aliceSecretKey);
        //        var alicePublicKeyStr = Convert.ToBase64String(alicePublicKey);


        //        Curve25519XSalsa20Poly1305.KeyPair(out var bobSecretKey, out var bobPublicKey);
        //        var bobSecretKeyStr = Convert.ToBase64String(aliceSecretKey);
        //        var bobPublicKeyStr = Convert.ToBase64String(alicePublicKey);

        //        Curve25519XSalsa20Poly1305 aliceBox = new Curve25519XSalsa20Poly1305(aliceSecretKey, bobPublicKey);
        //        Curve25519XSalsa20Poly1305 bobBox = new Curve25519XSalsa20Poly1305(bobSecretKey, alicePublicKey);

        //        // Generating random nonce
        //        byte[] nonce = new byte[Curve25519XSalsa20Poly1305.NonceLength];
        //        rng.GetBytes(nonce);

        //        // Plaintext message
        //        byte[] message = Encoding.UTF8.GetBytes("Hey Bob");

        //        // Prepare the buffer for the ciphertext, must be message length and extra 16 bytes for the authentication tag
        //        byte[] cipher = new byte[message.Length + Curve25519XSalsa20Poly1305.TagLength];

        //        // Encrypting using alice box
        //        aliceBox.Encrypt(cipher, message, nonce);

        //        // Decrypting using bob box
        //        byte[] plain = new byte[cipher.Length - Curve25519XSalsa20Poly1305.TagLength];
        //        bool isVerified = bobBox.TryDecrypt(plain, cipher, nonce);

        //        Console.WriteLine("Verified: {0}", isVerified);
        //        Console.WriteLine("Message: {0}", Encoding.UTF8.GetString(plain));
        //    }

        //    return key;
        //}
        //public void Encrypt()
        //{
        //    //var key = new byte[32];
        //    //RandomNumberGenerator.Create().GetBytes(key);
        //    //// Create the primitive
        //    //var aead = new ChaCha20Poly1305(key);

        //    //// Use the primitive to encrypt a plaintext
        //    //aead.Encrypt(nonce, plaintext, ciphertext, tag, aad);

        //    //// ... or to decrypt a ciphertext
        //    //aead.Decrypt(nonce, ciphertext, tag, plaintext, aad);
        //}

        //public void Sign()
        //{
        //    //// Use the primitive to compute a tag
        //    //Poly1305.ComputeMac(key, data, tag);

        //    //// ... or to verify a tag
        //    //Poly1305.VerifyMac(key, data, tag);

        //}
    }
}

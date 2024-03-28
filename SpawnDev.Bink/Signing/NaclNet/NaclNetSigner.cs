//using Bink.Encryption.Asymmetric.NaclNet;
//using Bink.Hashing;
//using NaCl;
//using System;
//using System.Collections.Generic;
//using System.Linq;
////using System.Security.Cryptography;
//using System.Text;
//using System.Threading.Tasks;
//using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;

//namespace Bink.Signing.NaclNet
//{
//    // Typical encryption usage example
//    //• Generate a random AES key.
//    //• Use the AES key to encrypt the packet.
//    //• Hash the encrypted packet using SHA-256.
//    //• Read Alice’s RSA secret key from “wire format.”
//    //• Use Alice’s RSA secret key to sign the hash.
//    //• Read Bob’s RSA public key from wire format.
//    //• Use Bob’s public key to encrypt the AES key, hash, and signature.
//    //• Convert the encrypted key, hash, and signature to wire format.
//    //• Concatenate with the encrypted packet.
//    // https://cr.yp.to/highspeed/naclcrypto-20090310.pdf
    
//    // https://github.com/somdoron/NaCl.net
//    public class NaclNetSigner : SignerBase
//    {
//        public const string AsymType = "NACL";

//        private NaclNetAsymmetricEncryption naclAsymc = new NaclNetAsymmetricEncryption();

//        // might not be the right way, doing it for now until corrected
//        // usign shared keypair allows us to sign/verify and encrypt/decrypt likfe our AES does
//        private static string sharedPrivateKey = "qKy3fo7m/O0bEk6DbD0Mqltwna2HMvpnHXsqnBovkQA=";
//        private static string sharedPublicKey = "Fudx0AuU4moZYB8S3o418H/p6vUt1NIFOfsSGyHTmFk=";
//        static byte[] sharedPrivateKeyBytes = Convert.FromBase64String(sharedPrivateKey);
//        static byte[] sharedPublicKeyBytes = Convert.FromBase64String(sharedPublicKey);
//        BinkSHA1 BinkSHA1 = new BinkSHA1();

//        public override int PrivateKeySize { get; }
//        public override int PublicKeySize { get; }
//        public override int TokenSize { get; }

//        public NaclNetSigner()
//        {
//            KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
//            PrivateKeySize = privateKey.Length;
//            PublicKeySize = publicKey.Length;
//            var token = Sign(privateKey, privateKey);
//            TokenSize = token.Length;
//        }

//        public override string KeyToString(byte[] key) => Convert.ToBase64String(key);
//        public override byte[] KeyToBytes(string key) => Convert.FromBase64String(key);
//        public override string TokenToString(byte[] token) => Convert.ToBase64String(token);
//        public override byte[] TokenToBytes(string token) => Convert.FromBase64String(token);

//        public byte[] NonceCreate()
//        {
//            using (var rng = RandomNumberGenerator.Create())
//            {
//                byte[] nonce = new byte[Curve25519XSalsa20Poly1305.NonceLength];
//                rng.GetBytes(nonce);
//                return nonce;
//            }
//        }

//        #region KeyPair
//        public override bool KeyPairFromString(string keyPairString, out byte[] privateKey, out byte[] publicKey)
//        {
//            privateKey = default(byte[]);
//            publicKey = default(byte[]);
//            if (!KeyPairFromString(keyPairString, out string privateKeyStr, out string publicKeyStr)) return false;
//            (privateKey, publicKey) = (Convert.FromBase64String(privateKeyStr), Convert.FromBase64String(publicKeyStr));
//            return true;
//        }

//        public override bool KeyPairFromString(string keyPairString, out string privateKey, out string publicKey)
//        {
//            privateKey = "";
//            publicKey = "";
//            if (string.IsNullOrEmpty(keyPairString) || !keyPairString.Contains("|")) return false;
//            var p = keyPairString.Split('|');
//            (privateKey, publicKey) = (p[0], p[1]);
//            return true;
//        }

//        public override string KeyPairToString(string privateKey, string publicKey)
//        {
//            return $"{privateKey}|{publicKey}";
//        }

//        public override string KeyPairToString(byte[] privateKey, byte[] publicKey)
//        {
//            return KeyPairToString(KeyToString(privateKey), KeyToString(publicKey));
//        }

//        public override void KeyPairCreate(out string privateKey, out string publicKey)
//        {
//            Curve25519XSalsa20Poly1305.KeyPair(out var privateKeyBytes, out var publicKeyBytes);
//            privateKey = KeyToString(privateKeyBytes);
//            publicKey = KeyToString(publicKeyBytes);
//        }

//        public override void KeyPairCreate(out byte[] privateKey, out byte[] publicKey)
//        {
//            Curve25519XSalsa20Poly1305.KeyPair(out privateKey, out publicKey);
//        }
//        #endregion

//        public override bool Verify(byte[] originalMessage, byte[] tokenBytes, byte[] publicKeyBytes)
//        {
//            if (originalMessage == null || originalMessage.Length == 0) return false;
//            if (tokenBytes == null || tokenBytes.Length == 0) return false;
//            if (publicKeyBytes == null || publicKeyBytes.Length == 0) return false;
//            try
//            {
//                var decHash = naclAsymc.Decrypt(tokenBytes, sharedPrivateKeyBytes, publicKeyBytes);
//                var messageHash = BinkSHA1.HashBytes(originalMessage);
//                var ret = decHash.SequenceEqual(messageHash);
//                return ret;
//            }
//            catch { }
//            return false;
//        }
//        public override bool Verify(byte[] originalMessage, byte[] token, string signerPublicKey)
//        {
//            return Verify(originalMessage, token, KeyToBytes(signerPublicKey));
//        }
//        public override byte[] Sign(byte[] message, byte[] privateKeyBytes)
//        {
//            var hash = BinkSHA1.HashBytes(message);
//            var token = naclAsymc.Encrypt(hash, sharedPublicKeyBytes, privateKeyBytes);
//            return token;
//        }
//        public override byte[] Sign(byte[] message, string signerPrivateKey)
//        {
//            return Sign(message, KeyToBytes(signerPrivateKey));
//        }
//    }
//}

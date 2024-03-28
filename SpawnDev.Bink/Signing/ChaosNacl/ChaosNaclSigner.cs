using Chaos.NaCl;
using System;
using System.Collections.Generic;
using System.Linq;
//using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using RandomNumberGenerator = System.Security.Cryptography.RandomNumberGenerator;

namespace Bink.Signing.ChaosNacl
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
    public class ChaosNaclSigner : SignerBase
    {
        //public static readonly string AsymType = "NACL";
        public override int PrivateKeySize { get; }
        public override int PublicKeySize { get; }
        public override int TokenSize { get; }

        public override string Algorithm { get; } = "ChaosNacl";
        public override string KeyType { get; } = "EC"; // Nacl Ellyptic Curve

        public const int NonceSize = 24;

        public ChaosNaclSigner()
        {
            KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
            PrivateKeySize = privateKey.Length;
            PublicKeySize = publicKey.Length;
            var token = Sign(privateKey, privateKey);
            TokenSize = token.Length;
        }

        public override string KeyToString(byte[] key) => BytesToHex(key);
        public override byte[] KeyToBytes(string key) => HexToBytes(key);
        public override string TokenToString(byte[] token) => BytesToHex(token);
        public override byte[] TokenToBytes(string token) => HexToBytes(token);

        public byte[] NonceCreate() => GetBytes(NonceSize);

        #region KeyPair
        public override bool KeyPairFromString(string keyPairString, out byte[] privateKey, out byte[] publicKey)
        {
            privateKey = default(byte[]);
            publicKey = default(byte[]);
            if (!KeyPairFromString(keyPairString, out string privateKeyStr, out string publicKeyStr)) return false;
            (privateKey, publicKey) = (KeyToBytes(privateKeyStr), KeyToBytes(publicKeyStr));
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
            KeyPairCreate(out byte[] privateKeyBytes, out byte[] publicKeyBytes);
            privateKey = KeyToString(privateKeyBytes);
            publicKey = KeyToString(publicKeyBytes);
        }

        byte[] PrivateKeySeedFromExpandedPrivateKey(byte[] expandedPrivateKey)
        {
            if (expandedPrivateKey.Length == 32) return expandedPrivateKey;
            byte[] ret = new byte[32];
            Buffer.BlockCopy(expandedPrivateKey, 0, ret, 0, 32);
            return ret;
        }

        byte[] ExpandedPrivateKeyFromSeed(byte[] privateKeySeed)
        {
            return Ed25519.ExpandedPrivateKeyFromSeed(privateKeySeed);
        }

        byte[] PublicKeyFromSeed(byte[] privateKeySeed)
        {
            // WARNING: The returned public key will be different every call
            return Ed25519.PublicKeyFromSeed(privateKeySeed);
        }

        void SeparatePublicKeyParts(byte[] publicKey, out byte[] encryptionPublicKey, out byte[] signingPublicKey)
        {
            encryptionPublicKey = new byte[32];
            signingPublicKey = new byte[32];
            Buffer.BlockCopy(publicKey, 0, encryptionPublicKey, 0, 32);
            Buffer.BlockCopy(publicKey, 32, signingPublicKey, 0, 32);
        }

        public override void KeyPairCreate(out byte[] privateKey, out byte[] publicKey)
        {
            byte[] privateKeySeed = GetBytes(32);
            //using (var rng = RandomNumberGenerator.Create())
            //{
            //    privateKeySeed = new byte[32];
            //    rng.GetBytes(privateKeySeed);
            //}
            // the signing and encyption public keys are different. merge them and we'll separate them before use
            var encryptionPublicKey = MontgomeryCurve25519.GetPublicKey(privateKeySeed);
            Ed25519.KeyPairFromSeed(out byte[] signPublicKey, out byte[] expandedPrivateKey, privateKeySeed);
            privateKey = expandedPrivateKey;
            publicKey = encryptionPublicKey.Concat(signPublicKey).ToArray();
        }
        #endregion


        public override bool Verify(byte[] originalMessage, byte[] tokenBytes, byte[] publicKeyBytes)
        {
            if (originalMessage == null || originalMessage.Length == 0) return false;
            if (tokenBytes == null || tokenBytes.Length == 0) return false;
            if (publicKeyBytes == null || publicKeyBytes.Length == 0) return false;
            SeparatePublicKeyParts(publicKeyBytes, out var encPublicKey, out var signPublicKey);
            try
            {
                return Ed25519.Verify(tokenBytes, originalMessage, signPublicKey);
            }
            catch
            {
                return false;
            }
        }
        public override bool Verify(byte[] originalMessage, byte[] token, string signerPublicKey)
        {
            return Verify(originalMessage, token, KeyToBytes(signerPublicKey));
        }
        public override byte[] Sign(byte[] message, byte[] privateKeyBytes)
        {
            var token = Ed25519.Sign(message, privateKeyBytes);
            return token;
        }
        public override byte[] Sign(byte[] message, string signerPrivateKey)
        {
            return Sign(message, KeyToBytes(signerPrivateKey));
        }
    }
}

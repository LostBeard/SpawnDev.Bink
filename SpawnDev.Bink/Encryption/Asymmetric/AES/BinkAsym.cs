//using System;
//using System.Collections.Generic;
//using System.Security.Cryptography;
//using System.Text;
//using System.Text.Json;
//using Bink.Extensions;

//namespace Bink.Encryption.Asymmetric.AES
//{
//    public class BinkAsym : BinkAsymBase
//    {
//        public const string AsymType = "AES";
//        public override BinkAsymKeyPair KeyPairCreate()
//        {
//            int dwKeySize = 2048;
//            using (RSA rsa = RSA.Create(dwKeySize))
//            {
//                var privateKey = rsa.ToXmlString(true);
//                var publicKey = GetPublicKey(privateKey);
//                var ret = new BinkAsymKeyPair(AsymType, privateKey, publicKey);
//                return ret;
//            }
//        }

//        public override BinkAsymKeyPair KeyPairFromString(string keyPairString)
//        {
//            var privateKey = keyPairString;
//            var publicKey = GetPublicKey(privateKey);
//            var ret = new BinkAsymKeyPair(AsymType, privateKey, publicKey);
//            return ret;
//        }

//        public override string KeyPairToString(BinkAsymKeyPair keyPair)
//        {
//            var keyPairString = keyPair.PrivateKey;
//            return keyPairString;
//        }

//        public int GetMaxDataSizeToEncrypt(int dwKeySize = 2048)
//        {
//            return (dwKeySize / 8) - 11;
//        }

//        //public string GenerateKeyPair(int dwKeySize = 2048)
//        //{
//        //    using (RSA rsa = new RSACryptoServiceProvider(dwKeySize))
//        //    {
//        //        return rsa.ToXmlString(true);
//        //    }
//        //}

//        string GetPublicKey(string privateKeyPair)
//        {
//            using (RSA rsa = new RSACryptoServiceProvider())
//            {
//                rsa.FromXmlString(privateKeyPair);
//                return rsa.ToXmlString(false);
//            }
//        }

//        bool fOAEP = false; // if changed previosly encrypted data may not decrypt properly
//        // encrypt with recipients public key
//        // they will decrypt with their private key
//        public byte[] Encrypt(byte[] data, string publicKey)
//        {
//            byte[] ret = null;
//            using (var RSA = new RSACryptoServiceProvider())
//            {
//                RSA.FromXmlString(publicKey);
//                ret = RSA.Encrypt(data, fOAEP);
//            }
//            return ret;
//        }

//        public override byte[] Decrypt(byte[] data, byte[] privateKey)
//        {
//            return Decrypt(data, Encoding.UTF8.GetString(privateKey));
//        }

//        public byte[] Decrypt(byte[] data, string privateKey)
//        {
//            byte[] ret = null;
//            using (var RSA = new RSACryptoServiceProvider())
//            {
//                RSA.FromXmlString(privateKey);
//                ret = RSA.Decrypt(data, fOAEP);
//            }
//            return ret;
//        }

//        // verify the message was signed by the private key belongs to this public key
//        public bool Verify(byte[] originalMessage, byte[] token, string publicKey)
//        {
//            if (string.IsNullOrEmpty(publicKey)) return false;
//            bool success = false;
//            using (var rsa = new RSACryptoServiceProvider())
//            {
//                rsa.FromXmlString(publicKey);
//                using (SHA512Managed Hash = new SHA512Managed())
//                {
//                    byte[] hashedData = Hash.ComputeHash(token);
//                    success = rsa.VerifyData(originalMessage, CryptoConfig.MapNameToOID("SHA512"), token);
//                }
//            }
//            return success;
//        }
//        //public bool Verify(string originalMessage, string token, string publicKey)
//        //{
//        //    if (string.IsNullOrEmpty(publicKey)) return false;
//        //    return Verify(Encoding.UTF8.GetBytes(originalMessage), Convert.FromBase64String(token), publicKey); ;
//        //}

//        public bool Verify<T>(T signedObject, string publicKey, bool verifyTimestampIfExpirable = true) where T : ISignedObject
//        {
//            if (signedObject == null) return false;
//            if (string.IsNullOrEmpty(publicKey)) return false;
//            if (signedObject is IExpirableSignedObject tmp)
//            {
//                if (verifyTimestampIfExpirable && tmp.TokenExpiration > DateTime.MinValue)
//                {
//                    if (DateTime.UtcNow > tmp.TokenExpiration) return false;
//                }
//            }
//            var token = signedObject.Token;
//            signedObject.Token = "";
//            var origMessage = JsonSerializer.Serialize(signedObject);
//            signedObject.Token = token;
//            return Verify(origMessage, token, publicKey);
//        }

//        // sign with private key
//        // recipient will use the paired public key to verify the message
//        public byte[] Sign(byte[] message, string privateKey)
//        {
//            //// The array to store the signed message in bytes
//            byte[] signedBytes;
//            using (var rsa = new RSACryptoServiceProvider())
//            {
//                rsa.FromXmlString(privateKey);
//                signedBytes = rsa.SignData(message, CryptoConfig.MapNameToOID("SHA512"));
//            }
//            return signedBytes;
//        }

//        public T Sign<T>(T obj, string privateKey, DateTime expirationUtc) where T : IExpirableSignedObject
//        {
//            obj.Token = "";
//            obj.TokenExpiration = expirationUtc;
//            obj.TokenSigned = DateTime.UtcNow;
//            var origMessage = JsonSerializer.Serialize(obj);
//            obj.Token = Convert.ToBase64String(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
//            return obj;
//        }

//        public T Sign<T>(T obj, string privateKey, TimeSpan timeToLive) where T : IExpirableSignedObject
//        {
//            obj.Token = "";
//            obj.TokenExpiration = DateTime.UtcNow + timeToLive;
//            obj.TokenSigned = DateTime.UtcNow;
//            var origMessage = JsonSerializer.Serialize(obj);
//            obj.Token = Convert.ToBase64String(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
//            return obj;
//        }

//        public T Sign<T>(T obj, string privateKey) where T : ISignedObject
//        {
//            obj.Token = "";
//            if (obj is IExpirableSignedObject tmp1)
//            {
//                tmp1.TokenExpiration = DateTime.MinValue;
//            }
//            obj.TokenSigned = DateTime.UtcNow;
//            var origMessage = JsonSerializer.Serialize(obj);
//            var token = Convert.ToBase64String(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
//            obj.Token = token;
//            return obj;
//        }

//        public Dictionary<string, object> Sign(Dictionary<string, object> obj, string privateKey, TimeSpan timeToLive)
//        {
//            return Sign(obj, privateKey, DateTime.UtcNow + timeToLive);
//        }

//        public Dictionary<string, object> Sign(Dictionary<string, object> obj, string privateKey)
//        {
//            return Sign(obj, privateKey, DateTime.MinValue);
//        }

//        public Dictionary<string, object> Sign(Dictionary<string, object> obj, string privateKey, DateTime expirationUtc)
//        {
//            obj.Unset("Token");
//            if (expirationUtc == DateTime.MinValue)
//            {
//                obj.Unset("TokenExpiration");
//                obj.Unset("TokenSigned");
//            }
//            else
//            {
//                obj.Set("TokenExpiration", expirationUtc);
//                obj.Set("TokenSigned", DateTime.UtcNow);
//            }
//            var origMessage = JsonSerializer.Serialize(obj);
//            var token = Convert.ToBase64String(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
//            obj.Set("Token", token);
//            return obj;
//        }

//        public bool Verify(Dictionary<string, object> signedObject, string publicKey, bool verifyTimestampIfExpirable = true)
//        {
//            if (signedObject == null) return false;
//            if (string.IsNullOrEmpty(publicKey)) return false;
//            var expirationIsSet = signedObject.IsSet("TokenExpiration");
//            if (expirationIsSet)
//            {
//                var expiration = signedObject.Get<DateTime>("TokenExpiration");
//                if (verifyTimestampIfExpirable && expiration > DateTime.MinValue && DateTime.UtcNow > expiration)
//                {
//                    return false;
//                }
//            }
//            var token = signedObject.Get<string>("Token");
//            signedObject.Unset("Token");
//            var origMessage = JsonSerializer.Serialize(signedObject);
//            signedObject.Set("Token", token);
//            return Verify(origMessage, token, publicKey);
//        }

//        public string Sign(string message, string privateKey)
//        {
//            return Convert.ToBase64String(Sign(Encoding.UTF8.GetBytes(message), privateKey));
//        }
//    }
//}

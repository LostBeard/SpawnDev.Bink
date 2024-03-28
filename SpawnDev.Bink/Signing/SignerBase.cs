using Bink.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Bink.Signing
{
    public abstract class SignerBase
    {
        public static byte[] GetBytes(int length)
        {
            var ret = new byte[length];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(ret);
            }
            return ret;
        }
        public abstract int PrivateKeySize { get; }
        public abstract int PublicKeySize { get; }
        public abstract int TokenSize { get; }

        public AsymKeyPair KeyPairCreate(string keyName = "")
        {
            KeyPairCreate(out string privateKey, out string publicKey);
            return new AsymKeyPair(Algorithm, privateKey, publicKey, keyName);
        }
        public AsymKeyPairB KeyPairBCreate(string keyName = "")
        {
            KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
            return new AsymKeyPairB(Algorithm, privateKey, publicKey, keyName);
        }

        public abstract string KeyPairToString(string privateKey, string publicKey);
        public abstract string KeyPairToString(byte[] privateKey, byte[] publicKey);
        public abstract void KeyPairCreate(out string privateKey, out string publicKey);
        public abstract void KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
        public abstract bool KeyPairFromString(string keyPairString, out string privateKey, out string publicKey);
        public abstract bool KeyPairFromString(string keyPairString, out byte[] privateKey, out byte[] publicKey);

        public bool Verify(string originalMessage, byte[] token, byte[] signerPublicKey)
        {
            return Verify(Encoding.UTF8.GetBytes(originalMessage), token, signerPublicKey);
        }
        public abstract bool Verify(byte[] originalMessage, byte[] token, byte[] signerPublicKey);
        public abstract bool Verify(byte[] originalMessage, byte[] token, string signerPublicKey);
        public abstract byte[] Sign(byte[] message, byte[] signerPrivateKey);
        public abstract byte[] Sign(byte[] message, string signerPrivateKey);
        public byte[] Sign(string message, string signerPrivateKey)
        {
            return Sign(Encoding.UTF8.GetBytes(message), signerPrivateKey);
        }
        public string SignToString(string message, string signerPrivateKey)
        {
            return TokenToString(Sign(Encoding.UTF8.GetBytes(message), KeyToBytes(signerPrivateKey)));
        }

        public bool Verify<T>(T signedObject, string publicKey, bool verifyTimestampIfExpirable = true) where T : ISignedObject
        {
            return Verify<T>(signedObject, KeyToBytes(publicKey), verifyTimestampIfExpirable);
        }

        public bool Verify<T>(T signedObject, byte[] publicKey, bool verifyTimestampIfExpirable = true) where T : ISignedObject
        {
            if (signedObject == null) return false;
            if (publicKey == null || publicKey.Length == 0) return false;
            if (signedObject is IExpirableSignedObject tmp)
            {
                if (verifyTimestampIfExpirable && tmp.TokenExpiration > DateTime.MinValue)
                {
                    if (DateTime.UtcNow > tmp.TokenExpiration) return false;
                }
            }
            var token = signedObject.Token;
            signedObject.Token = "";
            var origMessage = JsonSerializer.Serialize(signedObject);
            signedObject.Token = token;
            return Verify(origMessage, token, publicKey);
        }

        public bool Verify(string message, string token, byte[] publicKey)
        {
            return Verify(Encoding.UTF8.GetBytes(message), TokenToBytes(token), publicKey);
        }

        public bool Verify(JwtTokenReader tokenReader, byte[] publicKeyBytes, bool requireValid = true)
        {
            if (requireValid && !tokenReader.IsValid) return false;
            var verified = Verify(tokenReader.SignedSection, tokenReader.SignatureBytes, publicKeyBytes);
            tokenReader.Verified = verified;
            return verified;
        }

        /// <summary>
        /// Can be used to verify tokens that provide a kid and jku
        /// </summary>
        /// <param name="tokenReader"></param>
        /// <param name="requireValid"></param>
        /// <returns></returns>
        public async Task<bool> Verify(JwtTokenReader tokenReader, bool requireValid = true)
        {
            if (requireValid && !tokenReader.IsValid) return false;
            var publicKey = await tokenReader.GetPublicKeyFromJku();
            if (string.IsNullOrEmpty(publicKey)) return false;
            var verified = Verify(tokenReader.SignedSection, tokenReader.SignatureBytes, KeyToBytes(publicKey));
            tokenReader.Verified = verified;
            return verified;
        }

        public bool Verify(JwtTokenReader tokenReader, string publicKey, bool requireValid = true)
        {
            if (requireValid && !tokenReader.IsValid) return false;
            var verified = Verify(tokenReader.SignedSection, tokenReader.SignatureBytes, KeyToBytes(publicKey));
            tokenReader.Verified = verified;
            return verified;
        }

        public Dictionary<string, byte[]> Sign(byte[] message, Dictionary<string, byte[]> privateKeys)
        {
            var ret = new Dictionary<string, byte[]>();
            foreach (var kvp in privateKeys)
            {
                var sig = Sign(message, kvp.Value);
                ret.Add(kvp.Key, sig);
            }
            return ret;
        }

        public Dictionary<string, byte[]> Sign(string message, Dictionary<string, byte[]> privateKeys)
        {
            var ret = new Dictionary<string, byte[]>();
            foreach (var kvp in privateKeys)
            {
                var sig = Sign(Encoding.UTF8.GetBytes(message), kvp.Value);
                ret.Add(kvp.Key, sig);
            }
            return ret;
        }

        public byte[] Sign(string message, byte[] privateKey)
        {
            return Sign(Encoding.UTF8.GetBytes(message), privateKey);
        }

        public void Sign<T>(T obj, string privateKey, DateTime expirationUtc) where T : IExpirableSignedObject
        {
            Sign<T>(obj, KeyToBytes(privateKey), expirationUtc);
        }

        public void Sign<T>(T obj, byte[] privateKey, DateTime expirationUtc) where T : IExpirableSignedObject
        {
            obj.Token = "";
            obj.Alg = Algorithm;
            obj.TokenExpiration = expirationUtc;
            obj.TokenSigned = DateTime.UtcNow;
            var origMessage = JsonSerializer.Serialize(obj);
            obj.Token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
        }

        public void Sign<T>(T obj, string privateKey, TimeSpan timeToLive) where T : IExpirableSignedObject
        {
            Sign<T>(obj, KeyToBytes(privateKey), timeToLive);
        }

        public void Sign<T>(T obj, byte[] privateKey, TimeSpan timeToLive) where T : IExpirableSignedObject
        {
            obj.Token = "";
            obj.Alg = Algorithm;
            obj.TokenExpiration = DateTime.UtcNow + timeToLive;
            obj.TokenSigned = DateTime.UtcNow;
            var origMessage = JsonSerializer.Serialize(obj);
            obj.Token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
        }

        public byte[] PublicKeyToRGB(AsymKeyPair keys, int size = 64)
        {
            return PublicKeyToRGB(keys.PublicKey, size);
        }
        public byte[] PublicKeyToRGB(string publicKey, int size = 64)
        {
            var bytes = KeyToBytes(publicKey);
            var ret = KeyFill(bytes, size * size * 3);
            return ret;
        }
        public byte[] PublicKeyToRGBA(AsymKeyPair keys, int size = 64)
        {
            return PublicKeyToRGBA(keys.PublicKey, size);
        }
        public byte[] PublicKeyToRGBA(string publicKey, int size = 64)
        {
            var bytes = KeyToBytes(publicKey);
            var pixelCount = size * size;
            var ret = new byte[pixelCount * 4];
            var bytesPtr = 0;
            for (var i = 0; i < ret.Length; i+=4)
            {
                ret[i] = bytes[bytesPtr];
                bytesPtr = bytesPtr == bytes.Length - 1 ? 0 : bytesPtr + 1;
                ret[i + 1] = bytes[bytesPtr];
                bytesPtr = bytesPtr == bytes.Length - 1 ? 0 : bytesPtr + 1;
                ret[i + 2] = bytes[bytesPtr];
                bytesPtr = bytesPtr == bytes.Length - 1 ? 0 : bytesPtr + 1;
                ret[i + 3] = 255;
            }
            return ret;
        }
        byte[] KeyFill(byte[] bytes, int size)
        {
            var ret = new byte[size];
            for (var i = 0; i < size; i += bytes.Length)
            {
                var bytesLeft = size - i;
                var cnt = Math.Min(bytesLeft, bytes.Length);
                Array.Copy(bytes, 0, ret, i, cnt);
            }
            return ret;
        }

        //public bool MultiVerifyWithinDeviation()
        //{

        //}

        public bool MultiVerify<T>(T obj, IEnumerable<string> requiredPublicKeys = null, TimeSpan? maxSignTimeDeviation = null, bool verifyTimestampIfExpirable = true) where T : IMultiSignedObject
        {
            var ret = true;
            if (obj.Signatures == null || obj.Signatures.Count == 0) return true;
            var now = DateTime.UtcNow;
            var sigs = obj.Signatures;
            obj.Signatures = new List<ExpirableSignature>();
            var requiredKeys = requiredPublicKeys == null ? null : new List<string>(requiredPublicKeys.Distinct());
            var maxDeviationSeconds = maxSignTimeDeviation != null ? maxSignTimeDeviation.Value.TotalSeconds : 0;
            while (sigs.Count > 0)
            {
                var sig = sigs.First();
                sigs.Remove(sig);
                var origMessage = JsonSerializer.Serialize(obj);
                obj.Signatures.Add(sig);
                var verified = Verify(origMessage, sig.Token, sig.PublicKey);
                if (!verified || verifyTimestampIfExpirable && now > sig.TokenExpiration)
                {
                    ret = false;
                    break;
                }
                if (maxSignTimeDeviation != null)
                {
                    var diffSeconds = (DateTime.UtcNow - sig.TokenSigned).TotalSeconds;
                    // TODO - probably should disallow signatures from too far into the future...
                    var deviation = Math.Abs(diffSeconds);
                    if (deviation > maxDeviationSeconds)
                    {
                        ret = false;
                        break;
                    }
                }
                if (requiredKeys != null && requiredKeys.Contains(sig.PublicKey))
                {
                    requiredKeys.Remove(sig.PublicKey);
                }
            }
            if (sigs.Count > 0)
            {
                obj.Signatures.AddRange(sigs);
            }
            if (ret && requiredKeys != null && requiredKeys.Any()) ret = false;
            return ret;
        }

        public bool MultiVerifyDesc<T>(T obj, bool verifyTimestampIfExpirable = true) where T : IMultiSignedObject
        {
            var ret = true;
            if (obj.Signatures == null || obj.Signatures.Count == 0) return true;
            var now = DateTime.UtcNow;
            var sigStash = new List<ExpirableSignature>();
            while (obj.Signatures.Count > 0)
            {
                var sig = obj.Signatures.Last();
                obj.Signatures.Remove(sig);
                sigStash.Add(sig);
                var origMessage = JsonSerializer.Serialize(obj);
                var verified = Verify(origMessage, sig.Token, sig.PublicKey);
                if (!verified || verifyTimestampIfExpirable && now > sig.TokenExpiration)
                {
                    ret = false;
                    break;
                }
            }
            if (sigStash.Count > 0)
            {
                sigStash.Reverse();
                obj.Signatures.AddRange(sigStash);
            }
            return ret;
        }

        public void MultiSign<T>(T obj, IEnumerable<AsymKeyPair> keySet, string keySetName = "") where T : IMultiSignedObject
        {
            foreach (var keys in keySet)
            {
                MultiSign(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, keySetName);
            }
        }
        public void MultiSign<T>(T obj, Dictionary<string, AsymKeyPair> keySet) where T : IMultiSignedObject
        {
            foreach (var kvp in keySet)
            {
                MultiSign(obj, KeyToBytes(kvp.Value.PrivateKey), kvp.Value.PublicKey, kvp.Key);
            }
        }
        public void MultiSign<T>(T obj, IEnumerable<AsymKeyPair> keySet, IEnumerable<string> keySetNames) where T : IMultiSignedObject
        {
            for (var i =0; i < keySet.Count();i++)
            {
                var keys = keySet.ElementAt(i);
                var key = keySetNames != null && i < keySetNames.Count() ? keySetNames.ElementAt(i) : "";
                MultiSign(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, key);
            }
        }
        public void MultiSign<T>(T obj, AsymKeyPair keys, string keyName = "") where T : IMultiSignedObject
        {
            MultiSign(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, keyName);
        }
        public void MultiSign<T>(T obj, string privateKey, string publicKey, string keyName = "") where T : IMultiSignedObject
        {
            MultiSign(obj, KeyToBytes(privateKey), publicKey, keyName);
        }

        public void MultiSign<T>(T tobj, byte[] privateKey, string publicKey, string keyName = "") where T : IMultiSignedObject
        {
            var obj = new ExpirableSignature();
            obj.KeyName = keyName;
            obj.Alg = Algorithm;
            obj.TokenExpiration = DateTime.MaxValue;
            obj.TokenSigned = DateTime.UtcNow;
            obj.PublicKey = publicKey;
            var origMessage = JsonSerializer.Serialize(tobj);
            obj.Token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
            tobj.Signatures.Add(obj);
        }
        public void MultiSign<T>(T obj, Dictionary<string, AsymKeyPair> keySet, TimeSpan timeToLive) where T : IMultiSignedObject
        {
            foreach (var kvp in keySet)
            {
                MultiSign(obj, KeyToBytes(kvp.Value.PrivateKey), kvp.Value.PublicKey, timeToLive, kvp.Key);
            }
        }
        public void MultiSign<T>(T obj, IEnumerable<AsymKeyPair> keySet, TimeSpan timeToLive, IEnumerable<string> keySetNames) where T : IMultiSignedObject
        {
            for (var i = 0; i < keySet.Count(); i++)
            {
                var keys = keySet.ElementAt(i);
                var key = keySetNames != null && i < keySetNames.Count() ? keySetNames.ElementAt(i) : "";
                MultiSign(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, timeToLive, key);
            }
        }
        public void MultiSign<T>(T obj, IEnumerable<AsymKeyPair> keySet, TimeSpan timeToLive, string keySetName = "") where T : IMultiSignedObject
        {
            foreach (var keys in keySet)
            {
                MultiSign(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, timeToLive, keySetName);
            }
        }
        public void MultiSign<T>(T obj, string privateKey, string publicKey, TimeSpan timeToLive, string keyName = "") where T : IMultiSignedObject
        {
            MultiSign<T>(obj, KeyToBytes(privateKey), publicKey, timeToLive, keyName);
        }
        public void MultiSign<T>(T obj, AsymKeyPair keys, TimeSpan timeToLive, string keyName = "") where T : IMultiSignedObject
        {
            MultiSign<T>(obj, KeyToBytes(keys.PrivateKey), keys.PublicKey, timeToLive, keyName);
        }

        public void MultiSign<T>(T tobj, byte[] privateKey, string publicKey, TimeSpan timeToLive, string keyName = "") where T : IMultiSignedObject
        {
            var obj = new ExpirableSignature();
            obj.KeyName = keyName;
            obj.Alg = Algorithm;
            obj.TokenExpiration = DateTime.UtcNow + timeToLive;
            obj.TokenSigned = DateTime.UtcNow;
            obj.PublicKey = publicKey;
            var origMessage = JsonSerializer.Serialize(tobj);
            obj.Token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
            tobj.Signatures.Add(obj);
        }

        public void Sign<T>(T obj, string privateKey) where T : ISignedObject
        {
            Sign<T>(obj, KeyToBytes(privateKey));
        }

        public void Sign<T>(T obj, byte[] privateKey) where T : ISignedObject
        {
            obj.Token = "";
            if (obj is IExpirableSignedObject tmp1)
            {
                tmp1.TokenExpiration = DateTime.MinValue;
            }
            obj.Alg = Algorithm;
            obj.TokenSigned = DateTime.UtcNow;
            var origMessage = JsonSerializer.Serialize(obj);
            var token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
            obj.Token = token;
        }

        public Dictionary<string, object> Sign(Dictionary<string, object> obj, byte[] privateKey, TimeSpan timeToLive)
        {
            return Sign(obj, privateKey, DateTime.UtcNow + timeToLive);
        }

        public Dictionary<string, object> Sign(Dictionary<string, object> obj, byte[] privateKey)
        {
            return Sign(obj, privateKey, DateTime.MinValue);
        }

        public Dictionary<string, object> Sign(Dictionary<string, object> obj, byte[] privateKey, DateTime expirationUtc)
        {
            obj.Unset("Token");
            if (expirationUtc == DateTime.MinValue)
            {
                obj.Unset("TokenExpiration");
                obj.Unset("TokenSigned");
            }
            else
            {
                obj.Set("TokenExpiration", expirationUtc);
                obj.Set("TokenSigned", DateTime.UtcNow);
            }
            var origMessage = JsonSerializer.Serialize(obj);
            var token = TokenToString(Sign(Encoding.UTF8.GetBytes(origMessage), privateKey));
            obj.Set("Token", token);
            return obj;
        }

        public bool Verify(Dictionary<string, object> signedObject, string publicKey, bool verifyTimestampIfExpirable = true)
        {
            if (signedObject == null) return false;
            if (string.IsNullOrEmpty(publicKey)) return false;
            var expirationIsSet = signedObject.IsSet("TokenExpiration");
            if (expirationIsSet)
            {
                var expiration = signedObject.Get<DateTime>("TokenExpiration");
                if (verifyTimestampIfExpirable && expiration > DateTime.MinValue && DateTime.UtcNow > expiration)
                {
                    return false;
                }
            }
            var token = signedObject.Get<string>("Token");
            signedObject.Unset("Token");
            var origMessage = JsonSerializer.Serialize(signedObject);
            signedObject.Set("Token", token);
            return Verify(origMessage, token, publicKey);
        }

        public bool Verify(string message, string token, string publicKey)
        {
            return Verify(Encoding.UTF8.GetBytes(message), TokenToBytes(token), KeyToBytes(publicKey));
        }

        [System.Diagnostics.Contracts.Pure]
        public static string BytesToHex(byte[] value)
        {
            if (value == null)
                throw new ArgumentNullException("value");

            const string hexAlphabet = @"0123456789ABCDEF";

            var chars = new char[checked(value.Length * 2)];
            unchecked
            {
                for (int i = 0; i < value.Length; i++)
                {
                    chars[i * 2] = hexAlphabet[value[i] >> 4];
                    chars[i * 2 + 1] = hexAlphabet[value[i] & 0xF];
                }
            }
            return new string(chars);
        }

        [System.Diagnostics.Contracts.Pure]
        public static byte[] HexToBytes(string value)
        {
            if (value == null)
                throw new ArgumentNullException("value");
            if (value.Length % 2 != 0)
                throw new ArgumentException("Hexadecimal value length must be even.", "value");

            unchecked
            {
                byte[] result = new byte[value.Length / 2];
                for (int i = 0; i < result.Length; i++)
                {
                    // 0(48) - 9(57) -> 0 - 9
                    // A(65) - F(70) -> 10 - 15
                    int b = value[i * 2]; // High 4 bits.
                    int val = ((b - '0') + ((('9' - b) >> 31) & -7)) << 4;
                    b = value[i * 2 + 1]; // Low 4 bits.
                    val += (b - '0') + ((('9' - b) >> 31) & -7);
                    result[i] = checked((byte)val);
                }
                return result;
            }
        }
        private static DateTime unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        private static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            var ret = unixEpoch + TimeSpan.FromSeconds(unixTimeStamp);
            return ret.ToUniversalTime();
        }

        private static double DateTimeToUnixTimeStamp(DateTime time)
        {
            var ret = time - unixEpoch;
            return ret.TotalSeconds;
        }

        private static long DateTimeToUnixTimeStampInt64(DateTime time)
        {
            var ret = time - unixEpoch;
            return (long)Math.Round(ret.TotalSeconds);
        }

        public string CreateJwtToken(List<Claim> claims, string privateKey, DateTime? expiration = null)
        {
            return CreateJwtToken(claims, KeyToBytes(privateKey), expiration);
        }

        public string CreateJwtToken(List<Claim> claims, byte[] privateKey, DateTime? expiration = null)
        {
            var claimsKVPList = new List<KeyValuePair<string, object>>();
            foreach (var claim in claims)
            {
                switch (claim.ValueType)
                {
                    case ClaimValueTypes.Integer:
                    case ClaimValueTypes.Integer32:
                    case ClaimValueTypes.Integer64:
                        if (long.TryParse(claim.Value, out var valueUlong))
                            claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, valueUlong.ToString()));
                        break;
                    case ClaimValueTypes.UInteger32:
                    case ClaimValueTypes.UInteger64:
                        if (ulong.TryParse(claim.Value, out var valueLong))
                            claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, valueLong.ToString()));
                        break;
                    case ClaimValueTypes.Double:
                        if (double.TryParse(claim.Value, out var valueDouble))
                            claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, valueDouble.ToString()));
                        break;
                    case ClaimValueTypes.Boolean:
                        if (bool.TryParse(claim.Value, out var valueBool))
                            claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, valueBool.ToString()));
                        break;
                    case ClaimValueTypes.Email:
                    case ClaimValueTypes.String:
                        claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, claim.Value));
                        break;
                    default:
                        claimsKVPList.Add(new KeyValuePair<string, object>(claim.Type, claim.Value));
                        break;
                }
            }
            return CreateJwtToken(claimsKVPList, privateKey, expiration);
        }
        public string CreateJwtToken(List<KeyValuePair<string, object>> claims, byte[] privateKey, DateTime? expiration = null)
        {
            var now = DateTime.UtcNow;
            var header = new Dictionary<string, object>();
            var payload = new Dictionary<string, object>();
            header.Add("alg", Algorithm);
            header.Add("typ", "JWT");
            var keys = claims.Select(o => o.Key).Distinct().ToList();
            foreach (var key in keys)
            {
                var values = claims.Where(o => o.Key == key).Select(o => o.Value);
                payload.Add(key, values.Count() > 1 ? values : values.First());
            }
            if (expiration != null)
            {
                payload.Add("exp", DateTimeToUnixTimeStampInt64(expiration.Value));
            }
            var iat = DateTimeToUnixTimeStampInt64(now);
            payload.Add("iat", iat);
            payload.Add("nbf", iat);
            var token = CreateJwtToken(header, payload, privateKey);
            return token;
        }

        private string CreateJwtToken(Dictionary<string, object> header, Dictionary<string, object> claims, byte[] privateKey)
        {
            var headerBase64UrlEncoded = SerializeToBase64UrlEncoded(header);
            var payloadBase64UrlEncoded = SerializeToBase64UrlEncoded(claims);
            var msg = $"{headerBase64UrlEncoded}.{payloadBase64UrlEncoded}";
            var signatureBase64UrlEncoded = ToBase64UrlEncoded(Sign(msg, privateKey));
            var token = $"{msg}.{signatureBase64UrlEncoded}";
            return token;
        }

        public string SerializeToBase64UrlEncoded<T>(T obj)
        {
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(obj);
            return ToBase64UrlEncoded(jsonBytes);
        }

        public string ToBase64UrlEncoded(byte[] data)
        {
            return Base64EncodedToBase64UrlEncoded(Convert.ToBase64String(data));
        }

        static string Base64UrlEncodedToBase64Encoded(string base64UrlEncoded)
        {
            string incoming = base64UrlEncoded.Replace('_', '/').Replace('-', '+');
            switch (base64UrlEncoded.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return incoming;
        }

        static readonly char[] padding = { '=' };
        static string Base64EncodedToBase64UrlEncoded(string base64Encoded)
        {
            return base64Encoded.TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }

        public abstract string KeyType { get; }
        public abstract string Algorithm { get; }
        public abstract string KeyToString(byte[] key);
        public abstract byte[] KeyToBytes(string key);
        public abstract string TokenToString(byte[] token);
        public abstract byte[] TokenToBytes(string token);
    }
}

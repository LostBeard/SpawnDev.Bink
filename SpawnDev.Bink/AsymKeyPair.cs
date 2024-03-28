using System;

namespace Bink
{
    public class AsymKeyPair
    {
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public string Algorithm { get; set; } = "";
        public string KeyName { get; set; } = "";
        public string PrivateKey { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public AsymKeyPair() { }

        public AsymKeyPair(string algorithm, string publicKey, string keyName = "")
        {
            Algorithm = algorithm;
            PublicKey = publicKey;
            KeyName = string.IsNullOrEmpty(keyName) ? Guid.NewGuid().ToString() : keyName;
        }
        public AsymKeyPair(string algorithm, string privateKey, string publicKey, string keyName = "")
        {
            Algorithm = algorithm;
            PublicKey = publicKey;
            PrivateKey = privateKey;
            KeyName = string.IsNullOrEmpty(keyName) ? Guid.NewGuid().ToString() : keyName;
        }
        public AsymKeyPair ToSharable()
        {
            return new AsymKeyPair(Algorithm, PublicKey, KeyName);
        }
        
    }
    public class AsymKeyPairB
    {
        public DateTime Created { get; set; } = DateTime.UtcNow;
        public string Algorithm { get; set; } = "";
        public string KeyName { get; set; } = "";
        public byte[] PrivateKey { get; set; }
        public byte[] PublicKey { get; set; }
        public AsymKeyPairB() { }

        public AsymKeyPairB(string algorithm, byte[] publicKey, string keyName = "")
        {
            Algorithm = algorithm;
            PublicKey = publicKey;
            KeyName = string.IsNullOrEmpty(keyName) ? Guid.NewGuid().ToString() : keyName;
        }
        public AsymKeyPairB(string algorithm, byte[] privateKey, byte[] publicKey, string keyName = "")
        {
            Algorithm = algorithm;
            PublicKey = publicKey;
            PrivateKey = privateKey;
            KeyName = string.IsNullOrEmpty(keyName) ? Guid.NewGuid().ToString() : keyName;
        }
        public AsymKeyPairB ToSharable()
        {
            return new AsymKeyPairB(Algorithm, PublicKey, KeyName);
        }
    }
}

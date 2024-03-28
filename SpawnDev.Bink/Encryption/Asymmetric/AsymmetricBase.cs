namespace Bink.Encryption.Asymmetric
{
    public abstract class AsymmetricBase
    {
        // encrypt with recipients public key
        //public abstract byte[] Encrypt(byte[] data, byte[] publicKey);
        //// decrypt with private key (data was encrypted
        //public abstract byte[] Decrypt(byte[] data, byte[] privateKey);
        ////public abstract byte[] Sign(byte[] message, string privateKey);
        ////public abstract bool Verify(byte[] originalMessage, byte[] token, string publicKey);

        public abstract int PrivateKeySize { get; }
        public abstract int PublicKeySize { get; }

        public AsymKeyPair KeyPairCreate(string keyName = "")
        {
            KeyPairCreate(out string privateKey, out string publicKey);
            return new AsymKeyPair(privateKey, publicKey, keyName);
        }

        public abstract string KeyPairToString(string privateKey, string publicKey);
        public abstract string KeyPairToString(byte[] privateKey, byte[] publicKey);
        public abstract void KeyPairCreate(out string privateKey, out string publicKey);
        public abstract void KeyPairCreate(out byte[] privateKey, out byte[] publicKey);
        public abstract bool KeyPairFromString(string keyPairString, out string privateKey, out string publicKey);
        public abstract bool KeyPairFromString(string keyPairString, out byte[] privateKey, out byte[] publicKey);

        public abstract byte[] Decrypt(byte[] encryptedMessage, byte[] recipientPrivateKey, byte[] senderPublicKey);
        public abstract byte[] Decrypt(byte[] encryptedMessage, byte[] recipientPrivateKey);
        public abstract byte[] Decrypt(byte[] encryptedMessage, string recipientPrivateKey);
        public abstract byte[] Decrypt(byte[] encryptedMessage, string recipientPrivateKey, string senderPublicKey);

        public abstract byte[] Encrypt(byte[] message, byte[] recipientPublicKey, byte[] senderPrivateKey);
        public abstract byte[] Encrypt(byte[] message, byte[] recipientPublicKey);
        public abstract byte[] Encrypt(byte[] message, string recipientPublicKey, string senderPrivateKey);
        public abstract byte[] Encrypt(byte[] message, string recipientPublicKey);

        public abstract string KeyToString(byte[] key);
        public abstract byte[] KeyToBytes(string key);
        public abstract string TokenToString(byte[] token);
        public abstract byte[] TokenToBytes(string token);
    }
}

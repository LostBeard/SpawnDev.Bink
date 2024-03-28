using System.Security.Cryptography;

namespace Bink.Hashing
{
    public class BinkSHA256 : HasherBase
    {
        public override byte[] HashBytes(byte[] aBytes)
        {
            using (var x = SHA256.Create()) return x.ComputeHash(aBytes);
        }
    }
}

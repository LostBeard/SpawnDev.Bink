using System.Security.Cryptography;

namespace Bink.Hashing
{
    public class BinkSHA1 : HasherBase
    {
        public override byte[] HashBytes(byte[] aBytes)
        {
            using (var x = SHA1.Create()) return x.ComputeHash(aBytes);
        }
    }
}

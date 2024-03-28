using System.Security.Cryptography;

namespace Bink.Hashing
{
    public class BinkSHA512 : HasherBase
    {
        public override byte[] HashBytes(byte[] aBytes)
        {
            using (var x = SHA512.Create()) return x.ComputeHash(aBytes);
        }
    }
}

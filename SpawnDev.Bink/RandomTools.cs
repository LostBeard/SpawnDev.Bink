using System.Security.Cryptography;
using System.Text;

namespace Bink
{
    public static class RandomTools
    {
        public static string ToHex(byte[] aBytes)
        {
            var s = new StringBuilder();
            foreach (byte b in aBytes) s.Append(b.ToString("x2").ToLower());
            return s.ToString();
        }
        public static string RandomBase64String(int byteLength)
        {
            using (var rng = RandomNumberGenerator.Create())
            {
                byte[] nonce = new byte[byteLength];
                rng.GetBytes(nonce);
                return ToHex(nonce);
            }
        }
    }
}

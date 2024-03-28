using System.Text;

namespace Bink.Hashing
{
    public abstract class HasherBase
    {
        public Encoding DefaultTextEncoding = Encoding.UTF8;
        public bool UseBase64 = false;

        public static string ToHex(byte[] aBytes)
        {
            var s = new StringBuilder();
            foreach (byte b in aBytes) s.Append(b.ToString("x2").ToLower());
            return s.ToString();
        }

        public string Hash(string input, Encoding encoding = null)
        {
            if (encoding == null) encoding = DefaultTextEncoding;
            return Hash(encoding.GetBytes(input));
        }

        public string Hash(byte[] aBytes)
        {
            return ToHex(HashBytes(aBytes));
        }

        public byte[] HashBytes(string input, Encoding encoding = null)
        {
            return HashBytes((encoding == null ? DefaultTextEncoding : encoding).GetBytes(input));
        }
        public abstract byte[] HashBytes(byte[] aBytes);
    }
}

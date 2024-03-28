namespace Bink.Hashing
{
    public class BinkMD5 : HasherBase
    {
        // System.Security.Cryptography is not used as it is not platform independent. It fails on Blazor WASM
        public override byte[] HashBytes(byte[] aBytes)
        {
            return MD5.ComputeHash(aBytes);
        }
    }
}

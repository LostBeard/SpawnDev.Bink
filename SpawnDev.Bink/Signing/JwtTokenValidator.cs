//using System;
//using System.Collections.Generic;
//using System.Linq;
//using System.Net.Http;
//using System.Text;
//using System.Threading.Tasks;

//namespace Bink.Signing
//{
//    public class JwtTokenValidator
//    {
//        public List<SignerBase> Signers { get; set; } = new List<SignerBase>();

//        HttpClient _client = new HttpClient();

//        public List<string> TrustedJkuAddresses = new List<string>();

//        public void AddSigner<T>(T signer) where T : SignerBase
//        {
//            Signers.Add(signer);
//        }

//        public JwtTokenValidator()
//        {

//        }

//        public async Task<bool> ValidateToken(string token)
//        {
//            //var tokenReader = new JwtTokenReader(token);
//            //var signer = Signers.Where(o => o.Algorithm == tokenReader.HeaderAlg).FirstOrDefault();
//            //if (signer == null) return false;
//            //// get public key 
//            return false;
//        }
//    }
//}

using System.Collections.Generic;
using System.Text.Json.Serialization;

namespace Bink.Signing
{
    public class JWKS
    {
        [JsonPropertyName("keys")]
        public List<JwkKeysEntry> Keys { get; set; }
    }
    public class JwkKeysEntry
    {
        [JsonPropertyName("alg")]
        public string alg { get; set; } = "";
        [JsonPropertyName("kty")]
        public string kty { get; set; } = "";
        [JsonPropertyName("use")]
        public string use { get; set; } = "";
        [JsonPropertyName("iat")]
        public long iat { get; set; }
        [JsonPropertyName("kid")]
        public string kid { get; set; } = "";
        [JsonPropertyName("key")]
        public string key { get; set; } = "";
    }
}

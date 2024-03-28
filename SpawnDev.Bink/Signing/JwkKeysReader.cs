using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading.Tasks;

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
    //public class JWKS
    //{
    //    [JsonPropertyName("keys")]
    //    public List<Dictionary<string, JsonElement>> Keys { get; set; } = new List<Dictionary<string, JsonElement>>();
    //}
    //public class JwkKeysEntry
    //{
    //    public string Alg => Get("alg");
    //    public string Kty => Get("kty");
    //    public string Use => Get("use");
    //    public string Kid => Get("kid");
    //    public long Iat => Get<long>("iat");
    //    public Dictionary<string, JsonElement> KeyPairs { get; private set; } = new Dictionary<string, JsonElement>();
    //    public JwkKeysEntry(Dictionary<string, JsonElement> keyPairs)
    //    {
    //        KeyPairs = keyPairs;
    //    }
    //    public string Get(string key)
    //    {
    //        return Get<string>(key);
    //    }
    //    public T Get<T>(string key)
    //    {
    //        return KeyPairs.TryGetValue(key, out var tmp) ? tmp.Deserialize<T>() : default;
    //    }
    //}
    //public class JwkKeysReader
    //{
    //    //JWKS _JWKS = new JWKS();
    //    public List<JwkKeysEntry> Items { get; set; } = new List<JwkKeysEntry>();
    //    public JwkKeysReader()
    //    {

    //    }

    //    public JwkKeysReader(string jwksJSON)
    //    {
    //        var jwks = JsonSerializer.Deserialize<JWKS>(jwksJSON);
    //        foreach (var key in jwks.Keys)
    //        {
    //            Items.Add(new JwkKeysEntry(key));
    //        }
    //    }

    //    public string ToJSON()
    //    {
    //        var jwks = new JWKS();
    //        foreach(var item in Items)
    //        {
    //            jwks.Keys.Add(item.KeyPairs);
    //        }
    //        var json = JsonSerializer.Serialize(jwks);
    //        return json;
    //    }

    //    public void Add(Dictionary<string, object> keyValuePairs)
    //    {
    //        if (!keyValuePairs.TryGetValue("kid", out var kid) || !(kid is string) || string.IsNullOrEmpty((string)kid))
    //        {
    //            throw new Exception("kid must be specified");
    //        }
    //        var claims = new Dictionary<string, JsonElement>();
    //        foreach(var kvp in keyValuePairs)
    //        {
    //            var json = JsonSerializer.Serialize(kvp.Value);
    //            var jsonEl = JsonSerializer.Deserialize<JsonElement>(json);
    //            claims.Add(kvp.Key, jsonEl);
    //        }
    //        Items.Add(new JwkKeysEntry(claims));
    //    }

    //    public JwkKeysEntry GetKeyEntry(string kid)
    //    {
    //        return Items.Where(o => o.Kid == kid).FirstOrDefault();
    //    }
    //}
}

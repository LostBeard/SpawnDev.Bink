using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace Bink.Signing
{
    // https://auth0.com/docs/secure/tokens/json-web-tokens/validate-json-web-tokens
    public class JwtTokenReader
    {

        public static ClaimsPrincipal GetClaimsPrincipal(string token, bool allowExpired = false)
        {
            var tmp = new JwtTokenReader(token);
            return allowExpired ? tmp.ExpiredClaimsPrincipal : tmp.ClaimsPrincipal;
        }
        public string Token { get; private set; }
        public byte[] SignedSection { get; private set; } = new byte[0];
        public byte[] SignatureBytes { get; private set; } = new byte[0];
        public Dictionary<string, JsonElement> Header { get; private set; } = new Dictionary<string, JsonElement>();
        public Dictionary<string, JsonElement> Payload { get; private set; } = new Dictionary<string, JsonElement>();
        // Reserved claims
        public string Iss { get; private set; } = "";
        public string Sub { get; private set; } = "";
        public string Aud { get; private set; } = "";
        public string Kid { get; private set; } = "";
        public string Jku { get; private set; } = "";
        // Standard claims
        public DateTimeOffset Expiration { get; private set; } = DateTimeOffset.MaxValue;
        // Header
        public string HeaderTyp { get; private set; } = "";
        public string HeaderAlg { get; private set; } = "";
        //
        public bool Verified { get; set; }
        /// <summary>
        /// IsExpired is true if the parse succeeded and the token has expired
        /// </summary>
        public bool IsExpired { get; private set; }
        public bool ParseFailed { get; private set; }
        /// <summary>
        /// IsValid is true if the parse succeeded and the token has not expired
        /// </summary>
        public bool IsValid { get; private set; }   // this means it is not expired and has a valid structure
        /// <summary>
        /// Equal to the token's ClaimsPrincipal unless it has expired
        /// </summary>
        public ClaimsPrincipal ClaimsPrincipal { get; } = Anonymous;
        /// <summary>
        /// Equal to the token's ClaimsPrincipal even if it has expired
        /// </summary>
        public ClaimsPrincipal ExpiredClaimsPrincipal { get; } = Anonymous;
        public static ClaimsPrincipal Anonymous { get; } = new ClaimsPrincipal(new ClaimsIdentity());
        public JwtTokenReader(string token)
        {
            Token = token;
            if (string.IsNullOrWhiteSpace(Token))
            {
                ParseFailed = true;
                return;
            }
            var parts = Token.Split('.');
            if (parts.Length != 3)
            {
                ParseFailed = true;
                return;
            }
            SignedSection = Encoding.UTF8.GetBytes($"{parts[0]}.{parts[1]}");
            SignatureBytes = Base64UrlEncodedToBytes(parts[2]);
#if DEBUG && false
            byte[] HeaderBytes = Base64UrlEncodedToBytes(parts[0]);
            string HeaderStr = Encoding.UTF8.GetString(HeaderBytes);

            byte[] PayloadBytes = Base64UrlEncodedToBytes(parts[1]);
            string PayloadStr = Encoding.UTF8.GetString(PayloadBytes);
#endif
            Header = DeserializeBase64UrlEncoded<Dictionary<string, JsonElement>>(parts[0]);
            Payload = DeserializeBase64UrlEncoded<Dictionary<string, JsonElement>>(parts[1]);
            HeaderAlg = HeaderFindFirstValue("alg");
            HeaderTyp = HeaderFindFirstValue("typ");

            var exp = FindFirstValue<double>("exp");
            if (exp > 0)
            {
                Expiration = UnixTimeStampToDateTime(exp);
                IsExpired = DateTimeOffset.UtcNow > Expiration;
            }
            Kid = FindFirstValue("kid");
            Jku = FindFirstValue("jku");
            Iss = FindFirstValue("iss");
            Aud = FindFirstValue("aud");
            Sub = FindFirstValue("sub");
            var claims = new List<Claim>();
            foreach (var kvp in Payload)
            {
                ParseElement(claims, kvp.Key, kvp.Value);
            }
            var tokenClaimsPrincipal = new ClaimsPrincipal(new ClaimsIdentity(claims, this.GetType().Name));
            ExpiredClaimsPrincipal = tokenClaimsPrincipal;
            if (!IsExpired)
            {
                IsValid = true;
                ClaimsPrincipal = tokenClaimsPrincipal;
            }
        }

        JsonSerializerOptions JsonSerializerOptions = new JsonSerializerOptions { PropertyNameCaseInsensitive = true };

        private string _GetPublicKeyFromJkuResponse = "";
        public async Task<string> GetPublicKeyFromJku()
        {
            if (string.IsNullOrEmpty(Jku)) return "";
            if (string.IsNullOrEmpty(Kid)) return "";
            if (!string.IsNullOrEmpty(_GetPublicKeyFromJkuResponse))
            {
                return _GetPublicKeyFromJkuResponse;
            }
            var _client = new HttpClient();
            try
            {
                var resp = await _client.GetAsync(Jku);
                if (resp.IsSuccessStatusCode)
                {
                    var jwksJSON = await resp.Content.ReadAsStringAsync();
                    var jwks = JsonSerializer.Deserialize<JWKS>(jwksJSON, JsonSerializerOptions);
                    var entry = jwks.Keys.Where(o => o.kid == Kid).FirstOrDefault();
                    if (entry != null)
                    {
                        var publicKey = entry.key;
                        if (!string.IsNullOrEmpty(publicKey) && entry.alg == HeaderAlg)
                        {
                            _GetPublicKeyFromJkuResponse = publicKey;
                            return publicKey;
                        }
                    }
                }
            }
            catch { }
            return "";
        }

        private void ParseElement(List<Claim> claims, string type, JsonElement el)
        {
            switch (el.ValueKind)
            {
                case JsonValueKind.Array:
                    foreach (var el2 in el.EnumerateArray())
                    {
                        ParseElement(claims, type, el2);
                    }
                    break;
                case JsonValueKind.String:
                    claims.Add(new Claim(type, el.GetString()));
                    break;
                case JsonValueKind.Number:
                    if (el.TryGetInt64(out long longValue))
                    {
                        claims.Add(new Claim(type, longValue.ToString(), ClaimValueTypes.Integer64));
                    }
                    else
                    {
                        var dblValue = el.GetDouble();
                        claims.Add(new Claim(type, dblValue.ToString(), ClaimValueTypes.Double));
                    }
                    break;
                default:
                    var nmt = "";
                    break;
            }
        }

        private static object JsonElementToTypedValue(JsonElement jsonElement)
        {
            switch (jsonElement.ValueKind)
            {
                case JsonValueKind.Object:
                case JsonValueKind.Array:
                    throw new NotSupportedException();
                case JsonValueKind.String:
                    if (jsonElement.TryGetGuid(out Guid guidValue))
                    {
                        return guidValue;
                    }
                    else
                    {
                        if (jsonElement.TryGetDateTimeOffset(out DateTimeOffset datetime))
                        {
                            //if (datetime.Kind == DateTimeKind.Local)
                            //{
                            //    if (jsonElement.TryGetDateTimeOffset(out DateTimeOffset datetimeOffset))
                            //    {
                            //        return datetimeOffset;
                            //    }
                            //}
                            return datetime;
                        }
                        return jsonElement.ToString();
                    }
                case JsonValueKind.Number:
                    if (jsonElement.TryGetInt64(out long longValue))
                    {
                        return longValue;
                    }
                    else
                    {
                        return jsonElement.GetDouble();
                    }
                case JsonValueKind.True:
                case JsonValueKind.False:
                    return jsonElement.GetBoolean();
                case JsonValueKind.Undefined:
                case JsonValueKind.Null:
                    return null;
                default:
                    return jsonElement.ToString();
            }
        }

        public string FindFirstValue(string type)
        {
            var all = FindAll<string>(type);
            return all.FirstOrDefault();
        }
        public T FindFirstValue<T>(string type)
        {
            var all = FindAll<T>(type);
            return all.FirstOrDefault();
        }
        public List<string> FindAll(string type)
        {
            return FindAll<string>(type);
        }
        public List<T> FindAll<T>(string type)
        {
            var ret = new List<T>();
            if (Payload.TryGetValue(type, out var el))
            {
                if (el.ValueKind == JsonValueKind.Array)
                {
                    try
                    {
                        var tmp = DeserializeJsonElement<List<T>>(el);
                        if (tmp != null) ret = tmp;
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        var tmp = DeserializeJsonElement<T>(el);
                        ret.Add(tmp);
                    }
                    catch { }
                }
            }
            return ret;
        }

        public string HeaderFindFirstValue(string type)
        {
            var all = HeaderFindAll<string>(type);
            return all.FirstOrDefault();
        }
        public T HeaderFindFirstValue<T>(string type)
        {
            var all = HeaderFindAll<T>(type);
            return all.FirstOrDefault();
        }
        public List<string> HeaderFindAll(string type)
        {
            return HeaderFindAll<string>(type);
        }
        public List<T> HeaderFindAll<T>(string type)
        {
            var ret = new List<T>();
            if (Header.TryGetValue(type, out var el))
            {
                if (el.ValueKind == JsonValueKind.Array)
                {
                    try
                    {
                        var tmp = DeserializeJsonElement<List<T>>(el);
                        if (tmp != null) ret = tmp;
                    }
                    catch { }
                }
                else
                {
                    try
                    {
                        var tmp = DeserializeJsonElement<T>(el);
                        ret.Add(tmp);
                    }
                    catch { }
                }
            }
            return ret;
        }

        private static string SerializeToBase64UrlEncoded<T>(T obj)
        {
            var jsonBytes = JsonSerializer.SerializeToUtf8Bytes(obj);
            return ToBase64UrlEncoded(jsonBytes);
        }
        private static T DeserializeBase64UrlEncoded<T>(string base64UrlEncoded)
        {
            var jsonBytes = Base64UrlEncodedToBytes(base64UrlEncoded);
            return JsonSerializer.Deserialize<T>(jsonBytes);
        }
        private static string ToBase64UrlEncoded(byte[] data)
        {
            return Base64EncodedToBase64UrlEncoded(Convert.ToBase64String(data));
        }
        private static byte[] Base64UrlEncodedToBytes(string base64UrlEncoded)
        {
            string incoming = base64UrlEncoded.Replace('_', '/').Replace('-', '+');
            switch (base64UrlEncoded.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return Convert.FromBase64String(incoming);
        }
        private static string Base64UrlEncodedToBase64Encoded(string base64UrlEncoded)
        {
            string incoming = base64UrlEncoded.Replace('_', '/').Replace('-', '+');
            switch (base64UrlEncoded.Length % 4)
            {
                case 2: incoming += "=="; break;
                case 3: incoming += "="; break;
            }
            return incoming;
        }
        private static readonly char[] padding = { '=' };
        private static string Base64EncodedToBase64UrlEncoded(string base64Encoded)
        {
            return base64Encoded.TrimEnd(padding).Replace('+', '-').Replace('/', '_');
        }
        private static DateTimeOffset unixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        private static DateTimeOffset UnixTimeStampToDateTime(double unixTimeStamp)
        {
            var ret = unixEpoch + TimeSpan.FromSeconds(unixTimeStamp);
            return ret.ToUniversalTime();
        }
        private static long DateTimeToUnixTimeStampInt64(DateTimeOffset time)
        {
            var ret = time - unixEpoch;
            return (long)Math.Round(ret.TotalSeconds);
        }
        private static double DateTimeToUnixTimeStamp(DateTimeOffset time)
        {
            var ret = time - unixEpoch;
            return ret.TotalSeconds;
        }
        private static T DeserializeJsonElement<T>(JsonElement el)
        {
            return el.Deserialize<T>();
        }
    }
}

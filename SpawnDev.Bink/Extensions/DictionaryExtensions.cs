using System.Collections.Generic;
using System.Text.Json;

namespace Bink.Extensions
{
    public static class DictionaryExtensions
    {
        // simple
        public static T Get<T>(this Dictionary<string, object> dic, string key, T defaultValue)
        {
            lock(dic)
            {
                return dic.ContainsKey(key) ? (T)dic[key] : defaultValue;
            }
        }
        public static T Get<T>(this Dictionary<string, object> dic, string key)
        {
            lock (dic)
            {
                return dic.ContainsKey(key) ? (T)dic[key] : default(T);
            }
        }
        public static void Set<T>(this Dictionary<string, object> dic, string key, T value)
        {
            lock (dic)
            {
                dic[key] = value;
            }
        }
        public static void Unset(this Dictionary<string, object> dic, string key)
        {
            lock (dic)
            {
                if (dic.ContainsKey(key)) dic.Remove(key);
            }
        }
        public static bool IsSet(this Dictionary<string, object> dic, string key)
        {
            lock (dic)
            {
                return dic.ContainsKey(key);
            }
        }

        public static T Get<T>(this List<JsonElement> list, int index)
        {
            return list[index].Deserialize<T>();
        }

        public static T ToObject<T>(this JsonElement element)
        {
            var json = element.GetRawText();
            return JsonSerializer.Deserialize<T>(json);
        }

        //static BinkAsym BinkAsym = new BinkAsym();
        //// BinkAsym signing extensions
        //public static Dictionary<string, object> Sign(this Dictionary<string, object> obj, string privateKey, TimeSpan timeToLive)
        //{
        //    return BinkAsym.Sign(obj, privateKey, timeToLive);
        //}

        //public static Dictionary<string, object> Sign(this Dictionary<string, object> obj, string privateKey)
        //{
        //    return BinkAsym.Sign(obj, privateKey);
        //}

        //public static Dictionary<string, object> Sign(this Dictionary<string, object> obj, string privateKey, DateTime expirationUtc)
        //{
        //    return BinkAsym.Sign(obj, privateKey, expirationUtc);
        //}

        //public static bool Verify(this Dictionary<string, object> signedObject, string publicKey, bool verifyTimestampIfExpirable = true)
        //{
        //    return BinkAsym.Verify(signedObject, publicKey, verifyTimestampIfExpirable);
        //}

        //public static byte[] EncryptSym(this Dictionary<string, object> obj, string privateKey)
        //{
        //    var json = JsonSerializer.SerializeToUtf8Bytes(obj);
        //    return BinkSym.Encrypt(json, privateKey);
        //}
    }
}

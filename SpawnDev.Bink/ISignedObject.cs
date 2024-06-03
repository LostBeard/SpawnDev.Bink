using System;
using System.Collections.Generic;

namespace Bink
{
    public interface ISignedObject
    {
        string Alg { get; set; }
        string Token { get; set; }
        DateTime TokenSigned { get; set; }
    }
    public abstract class SignedObject : ISignedObject
    {
        public string Alg { get; set; } = "";
        public string Token { get; set; } = "";
        public DateTime TokenSigned { get; set; } = DateTime.MinValue;
    }
    public interface IExpirableSignedObject : ISignedObject
    {
        DateTime TokenExpiration { get; set; }
    }
    public abstract class ExpirableSignedObject : IExpirableSignedObject
    {
        public string Alg { get; set; } = "";
        public string Token { get; set; } = "";
        public DateTime TokenExpiration { get; set; } = DateTime.MinValue;
        public DateTime TokenSigned { get; set; } = DateTime.MinValue;
    }
    public class ExpirableSignature
    {
        public string KeyName { get; set; } = "";
        public string Alg { get; set; } = "";
        public string Token { get; set; } = "";
        public string PublicKey { get; set; } = "";
        public DateTime TokenExpiration { get; set; } = DateTime.MinValue;
        public DateTime TokenSigned { get; set; } = DateTime.MinValue;
    }
    public interface IMultiSignedObject
    {
        List<ExpirableSignature> Signatures { get; set; }
        Dictionary<string, string> Claims { get; set; }
    }
    public abstract class MultiSignedObject : IMultiSignedObject
    {
        public List<ExpirableSignature> Signatures { get; set; } = new List<ExpirableSignature>();
        public Dictionary<string, string> Claims { get; set; }
        public MultiSignedObject(Dictionary<string, string> claims) => (Claims) = (claims);
        public MultiSignedObject() { }
    }
    public class MultiSignedObject<T> : IMultiSignedObject
    {
        public Dictionary<string, string> Claims { get; set; }
        public T Value { get; set; }
        public List<ExpirableSignature> Signatures { get; set; } = new List<ExpirableSignature>();
        public MultiSignedObject(T value, Dictionary<string, string> claims = null) => (Value, Claims) = (value, claims);
    }
}

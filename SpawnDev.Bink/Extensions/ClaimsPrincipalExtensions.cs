//using System;
//using System.Linq;
//using System.Security.Claims;

//namespace Bink.Extensions
//{
//    public static class ClaimsPrincipalExtensions
//    {
//        public static T FindFirstValue<T>(this ClaimsPrincipal claimsPrincipal, string type) where T : IConvertible
//        {
//            var tmp = claimsPrincipal.Claims.Where(x => x.Type == type).FirstOrDefault();
//            if (tmp == null) return default;
//            return (T)Convert.ChangeType(tmp.Value, typeof(T));
//        }
//    }
//}

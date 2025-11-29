using System.Linq;
using System.Security.Claims;

namespace Bink.Extensions
{
    public static class ClaimsPrincipalExtensions
    {
        public static string FindFirstValue(this ClaimsPrincipal claimsPrincipal, string type)
        {
            var tmp = claimsPrincipal.Claims.Where(x => x.Type == type).FirstOrDefault();
            if (tmp == null) return null;
            return tmp.Value;
        }
    }
}
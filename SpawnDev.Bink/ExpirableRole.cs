
using System;

namespace Bink
{
    public class ExpirableRole
    {
        public string Role { get; set; } = "";
        public DateTime? Expiration { get; set; }
        public bool CanExpire => Expiration != null;
        public bool IsExpired()
        {
            return Expiration != null && DateTime.UtcNow > Expiration.Value;
        }
    }
}

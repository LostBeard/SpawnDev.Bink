using Bink.Extensions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text.Json;

namespace Bink
{
    public static class ClaimsPrincipalExtensions
    {
        /// <summary>
        /// Removes claims that have a 'exp' property that has a datetime in the past.
        /// </summary>
        /// <param name="_this"></param>
        public static void RemoveExpiredClaims(this ClaimsPrincipal _this)
        {
            foreach (var identity in _this.Identities)
            {
                var identClaims = identity.Claims.ToList();
                foreach (var claim in identClaims)
                {
                    var exp = ExpirationClaimValueAsDateTime(claim);
                    if (exp != null)
                    {
                        if (exp.Value < DateTime.UtcNow)
                        {
                            identity.TryRemoveClaim(claim);
                        }
                    }
                }
            }
        }

        // polyFill for NET48
        public static T? FindFirstValue<T>(this ClaimsPrincipal _this, string type)
        {
            var obj = _this.FindFirstValue(type);
            if (typeof(T) == typeof(string))
            {
                return (T?)(object)obj;
            }
            return JsonSerializer.Deserialize<T>(obj);
        }
        private static DateTime unixEpoch { get; } = new DateTime(1970, 1, 1, 0, 0, 0, 0, System.DateTimeKind.Utc);
        private static DateTime UnixTimeStampToDateTime(double unixTimeStamp)
        {
            var ret = unixEpoch + TimeSpan.FromSeconds(unixTimeStamp);
            return ret.ToUniversalTime();
        }
        public static bool IsExpired(this ClaimsPrincipal _this)
        {
            var now = DateTime.UtcNow;
            var expiration = _this.Expiration();
            return expiration > DateTime.MinValue && now > expiration;
        }
        public static DateTime Expiration(this ClaimsPrincipal _this) => UnixTimeStampToDateTime(_this.FindFirstValue<double>("exp"));
        public static bool LoggedIn(this ClaimsPrincipal _this) => !string.IsNullOrEmpty(_this.UserId());
        public static bool HasPublicKey(this ClaimsPrincipal _this) => !string.IsNullOrEmpty(_this.PublicKey());
        public static string PublicKey(this ClaimsPrincipal _this) => _this.FindFirstValue(AccountClaimTypes.PublicKey) ?? "";
        public static string Issuer(this ClaimsPrincipal _this) => _this.FindFirstValue("iss") ?? "";
        public static bool KeepVerified(this ClaimsPrincipal _this) => _this.FindFirstValue<bool>(AccountClaimTypes.KeepVerified);
        public static string LoginId(this ClaimsPrincipal _this) => _this.FindFirstValue(AccountClaimTypes.LoginId) ?? "";
        public static string DeviceName(this ClaimsPrincipal _this) => _this.FindFirstValue(AccountClaimTypes.DeviceName) ?? "";
        public static string UserId(this ClaimsPrincipal _this) => _this.FindFirstValue(ClaimTypes.NameIdentifier) ?? "";
        public static string UsernameInClaim(this ClaimsPrincipal _this) => _this.FindFirstValue(ClaimTypes.Name) ?? "";
        public static string Username(this ClaimsPrincipal _this)
        {
            var userName = _this.UsernameInClaim();
            return !string.IsNullOrEmpty(userName) ? userName : MakeGuestUserName(_this.PublicKey());
        }
        public static string MakeGuestUserName(string devicePublicKey) => string.IsNullOrEmpty(devicePublicKey) ? GuestUsernamePrefix : $"{GuestUsernamePrefix}{devicePublicKey.Substring(0, GuestUserDevicePublicKeyPrefixSize)}";
        public static string MakeGuestDeviceName(string devicePublicKey) => string.IsNullOrEmpty(devicePublicKey) ? GuestDevicePrefix : $"{GuestDevicePrefix}{devicePublicKey.Substring(0, GuestUserDevicePublicKeyPrefixSize)}";
        public static string GuestDevicePrefix { get; } = "GuestDevice";
        public static string GuestUsernamePrefix { get; } = "GuestUser";
        public static int GuestUserDevicePublicKeyPrefixSize { get; } = 20;
        public static bool IsGuestUsernameSimilar(string roomName)
        {
            return roomName.StartsWith(GuestUsernamePrefix);
        }
        public static bool IsGuestUsername(string userName)
        {
            return userName.StartsWith(GuestUsernamePrefix) && userName.Length == GuestUsernamePrefix.Length + GuestUserDevicePublicKeyPrefixSize;
        }
        public static bool IsGuestDevice(string deviceName)
        {
            return deviceName.StartsWith(GuestDevicePrefix) && deviceName.Length == GuestDevicePrefix.Length + GuestUserDevicePublicKeyPrefixSize;
        }
        public static string UsernameCharacter(this ClaimsPrincipal _this) => !_this.LoggedIn() ? "?" : _this.Username().Substring(0, 1).ToUpperInvariant();
        public static List<string> Roles(this ClaimsPrincipal _this, bool removeExpired = true)
        {
            return _this.ExpirableRoles(removeExpired).Select(o => o.Role).ToList();
        }
        public static ExpirableRole? ExpirableRole(this ClaimsPrincipal _this, string role, bool removeExpired = true)
        {
            return _this.ExpirableRoles(removeExpired).FirstOrDefault(o => o.Role.Equals(role, StringComparison.OrdinalIgnoreCase));
        }
        public static List<ExpirableRole> ExpirableRoles(this ClaimsPrincipal _this, bool removeExpired = true)
        {
            var ret = _this.FindAll(ClaimTypes.Role).Select(o =>
                new ExpirableRole
                {
                    Role = o.Value,
                    Expiration = ExpirationClaimValueAsDateTime(o),
                }).OrderByDescending(o => o.Expiration ?? DateTime.MaxValue).ToList();
            if (removeExpired)
            {
                ret = ret.Where(o => !o.IsExpired()).ToList();
            }
            return ret;
        }
        static DateTime? ExpirationClaimValueAsDateTime(Claim o)
        {
            return o.Properties.TryGetValue("exp", out var expStr) && !string.IsNullOrWhiteSpace(expStr) && DateTime.TryParse(expStr, out var d) ? d : null;
        }
        public static bool HasRole(this ClaimsPrincipal _this, string role) => _this.Roles().Contains(role, StringComparer.OrdinalIgnoreCase);
        public static bool IsAdministrator(this ClaimsPrincipal _this) => _this.HasRole(AccountRoleTypes.Administrator);

    }
}

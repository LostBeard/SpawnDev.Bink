using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Bink.Signing
{
    // System.IdentityModel.Tokens.Jwt
    // Summary:
    //     List of registered claims from different sources https://datatracker.ietf.org/doc/html/rfc7519#section-4
    public struct JwtClaimNames
    {
        public const string Actort = "actort";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        public const string Acr = "acr";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        public const string Amr = "amr";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Aud = "aud";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        public const string AuthTime = "auth_time";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-core-1_0.html#IDToken
        public const string Azp = "azp";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string Birthdate = "birthdate";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        public const string CHash = "c_hash";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-core-1_0.html#CodeIDToken
        public const string AtHash = "at_hash";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string Email = "email";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Exp = "exp";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string Gender = "gender";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string FamilyName = "family_name";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string GivenName = "given_name";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Iat = "iat";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Iss = "iss";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Jti = "jti";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
        public const string Name = "name";

        public const string NameId = "nameid";

        //
        // Summary:
        //     https://openid.net/specs/openid-connect-core-1_0.html#AuthRequest
        public const string Nonce = "nonce";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Nbf = "nbf";

        public const string Prn = "prn";

        //
        // Summary:
        //     http://openid.net/specs/openid-connect-frontchannel-1_0.html#OPLogout
        public const string Sid = "sid";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-4
        public const string Sub = "sub";

        //
        // Summary:
        //     https://datatracker.ietf.org/doc/html/rfc7519#section-5
        public const string Typ = "typ";

        public const string UniqueName = "unique_name";

        public const string Website = "website";

        // Custom entries
        public const string Role = "role";
    }
}

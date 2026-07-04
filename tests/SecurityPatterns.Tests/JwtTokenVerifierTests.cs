using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using FluentAssertions;
using Microsoft.IdentityModel.Tokens;
using SecurityPatterns.Core.Abstractions;
using SecurityPatterns.VerifiableToken.Implementations;
using Xunit;

namespace SecurityPatterns.Tests;

public class JwtTokenVerifierTests
{
    private const string ValidKeyBase64 = "YXBpLXNlY3VyaXR5LXBhdHRlcm5zLXNlY3JldC1rZXktMjAyNg==";
    private const string Issuer = "TestIssuer";
    private const string Audience = "TestAudience";

    private static (JwtTokenIssuer Issuer, JwtTokenVerifier Verifier) CreateIssuerAndVerifier(
        string? key = null, string? issuer = null, string? audience = null)
    {
        var issuerInstance = new JwtTokenIssuer(key ?? ValidKeyBase64, issuer ?? Issuer, audience ?? Audience);
        var verifierInstance = new JwtTokenVerifier(key ?? ValidKeyBase64, issuer ?? Issuer, audience ?? Audience);
        return (issuerInstance, verifierInstance);
    }

    [Fact]
    public void ValidateToken_WithValidToken_ShouldReturnTrueAndExtractAllClaims()
    {
        // Arrange
        var (issuer, verifier) = CreateIssuerAndVerifier();
        var claims = new Dictionary<string, string>
        {
            ["role"] = "Admin",
            ["scope"] = "thesis:read thesis:write"
        };

        TokenResult tokenResult = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(30));

        // Act
        bool isValid = verifier.ValidateToken(tokenResult.Token, out IDictionary<string, string>? extractedClaims);

        // Assert — Validation must succeed
        isValid.Should().BeTrue("a freshly issued token with correct credentials must validate");

        // Assert — Claims must be extracted
        extractedClaims.Should().NotBeNull("extracted claims must not be null for a valid token");

        // Assert — Standard JWT claims are present with correct values
        extractedClaims!["sub"].Should().Be("usr-001",
            "the sub claim must match the subjectId passed to GenerateToken");
        extractedClaims["unique_name"].Should().Be("moein",
            "the unique_name claim must match the username passed to GenerateToken");

        // Assert — Custom claims are present with correct values
        extractedClaims["role"].Should().Be("Admin",
            "the custom role claim must be preserved through issuance and verification");
        extractedClaims["scope"].Should().Be("thesis:read thesis:write",
            "the custom scope claim must be preserved through issuance and verification");

        // Assert — JTI claim is a valid GUID
        extractedClaims.ContainsKey("jti").Should().BeTrue("every token must include a jti claim");
        Guid.TryParse(extractedClaims["jti"], out _).Should().BeTrue("jti must be a valid GUID");
    }

    [Fact]
    public void ValidateToken_WithTamperedSignature_ShouldReturnFalse()
    {
        // Arrange
        var (issuer, verifier) = CreateIssuerAndVerifier();
        var claims = new Dictionary<string, string> { ["role"] = "Admin" };
        TokenResult tokenResult = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(30));

        // Tamper — modify the payload while keeping the original signature
        string[] parts = tokenResult.Token.Split(['.']);
        string payloadJson = DecodeBase64Url(parts[1]);
        string tamperedPayloadJson = payloadJson.Replace("\"role\":\"Admin\"", "\"role\":\"SuperAdmin\"", StringComparison.Ordinal);
        string tamperedPayloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(tamperedPayloadJson));
        string tamperedToken = $"{parts[0]}.{tamperedPayloadB64}.{parts[2]}";

        // Act
        bool isValid = verifier.ValidateToken(tamperedToken, out IDictionary<string, string>? extractedClaims);

        // Assert — Validation must fail because the HMAC no longer matches the modified payload
        isValid.Should().BeFalse("a tampered token must be rejected to mitigate CWE-347");
        extractedClaims.Should().BeNull("no claims must be returned from a tampered token");
    }

    [Fact]
    public void ValidateToken_WithExpiredToken_ShouldReturnFalse()
    {
        // Arrange — create an expired token directly (issuer rejects Expires < NotBefore at creation time)
        var (_, verifier) = CreateIssuerAndVerifier();
        var key = new SymmetricSecurityKey(Convert.FromBase64String(ValidKeyBase64));
        var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

        var expiredToken = new JwtSecurityToken(
            issuer: Issuer,
            audience: Audience,
            claims: [new Claim("role", "Admin")],
            notBefore: DateTime.UtcNow.AddSeconds(-10),
            expires: DateTime.UtcNow.AddSeconds(-5), // expired 5 seconds ago
            signingCredentials: signingCredentials);

        string expiredTokenString = new JwtSecurityTokenHandler().WriteToken(expiredToken);

        // Act
        bool isValid = verifier.ValidateToken(expiredTokenString, out IDictionary<string, string>? extractedClaims);

        // Assert — Validation must fail because the token is already expired
        isValid.Should().BeFalse("an expired token must be rejected to mitigate CWE-613");
        extractedClaims.Should().BeNull("no claims must be returned from an expired token");
    }

    [Fact]
    public void ValidateToken_WithWrongIssuer_ShouldReturnFalse()
    {
        // Arrange — issuer and verifier use different issuer values
        var (issuer, verifier) = CreateIssuerAndVerifier(issuer: "CorrectIssuer");
        var badVerifier = new JwtTokenVerifier(ValidKeyBase64, "WrongIssuer", Audience);

        var claims = new Dictionary<string, string>();
        TokenResult tokenResult = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(30));

        // Act
        bool isValid = badVerifier.ValidateToken(tokenResult.Token, out _);

        // Assert — Validation must fail because the issuer doesn't match
        isValid.Should().BeFalse("tokens from an unrecognized issuer must be rejected to mitigate CWE-287");
    }

    [Fact]
    public void ValidateToken_WithWrongAudience_ShouldReturnFalse()
    {
        // Arrange — issuer and verifier use different audience values
        var (issuer, verifier) = CreateIssuerAndVerifier(audience: "CorrectAudience");
        var badVerifier = new JwtTokenVerifier(ValidKeyBase64, Issuer, "WrongAudience");

        var claims = new Dictionary<string, string>();
        TokenResult tokenResult = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(30));

        // Act
        bool isValid = badVerifier.ValidateToken(tokenResult.Token, out _);

        // Assert — Validation must fail because the audience doesn't match
        isValid.Should().BeFalse("tokens intended for a different audience must be rejected to mitigate CWE-287");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void ValidateToken_WithNullOrEmptyToken_ShouldReturnFalse(string? token)
    {
        // Arrange
        var (_, verifier) = CreateIssuerAndVerifier();

        // Act
        bool isValid = verifier.ValidateToken(token!, out IDictionary<string, string>? extractedClaims);

        // Assert
        isValid.Should().BeFalse("null or empty tokens must be rejected immediately");
        extractedClaims.Should().BeNull("no claims must be returned for null/empty input");
    }

    [Fact]
    public void ValidateToken_ShouldRejectNoneAlgorithmTokens()
    {
        // Arrange — manually construct a JWT with algorithm "none" (simulating an attacker)
        string headerJson = """{"alg":"none","typ":"JWT"}""";
        string payloadJson = """{"sub":"hacker-001","unique_name":"attacker","role":"SuperAdmin"}""";
        string headerB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(headerJson));
        string payloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(payloadJson));
        string forgedToken = $"{headerB64}.{payloadB64}."; // empty signature

        var (_, verifier) = CreateIssuerAndVerifier();

        // Act
        bool isValid = verifier.ValidateToken(forgedToken, out IDictionary<string, string>? extractedClaims);

        // Assert — The "none" algorithm must be rejected to mitigate CVE-2015-9235
        isValid.Should().BeFalse("tokens with the 'none' algorithm must be rejected to mitigate CVE-2015-9235");
        extractedClaims.Should().BeNull("no claims must be returned from an unsigned token");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrowArgumentException_WhenSecretKeyIsTooShort(string? badKey)
    {
        // Arrange
        string shortKey = badKey?.Trim() == "" ? badKey! : Convert.ToBase64String(new byte[16]);

        // Act
        Action act = () => new JwtTokenVerifier(shortKey, Issuer, Audience);

        // Assert
        act.Should().Throw<ArgumentException>("a short key is cryptographically weak");
    }

    [Fact]
    public void ValidateToken_WithWrongKey_ShouldReturnFalse()
    {
        // Arrange — issuer uses one key, verifier uses a different key
        string key1 = "YXBpLXNlY3VyaXR5LXBhdHRlcm5zLXNlY3JldC1rZXktMjAyNg==";
        string key2 = "b3RoZXItc2VjdXJlLXNlY3JldC1rZXktZm9yLXRlc3RpbmctcHVycG9zZQ==";

        var issuer = new JwtTokenIssuer(key1, Issuer, Audience);
        var verifier = new JwtTokenVerifier(key2, Issuer, Audience); // different key!

        var claims = new Dictionary<string, string> { ["role"] = "Admin" };
        TokenResult tokenResult = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(30));

        // Act
        bool isValid = verifier.ValidateToken(tokenResult.Token, out _);

        // Assert — Signature verification must fail because the keys don't match
        isValid.Should().BeFalse("a token signed with a different key must be rejected (CWE-347)");
    }

    // ─── Helpers ────────────────────────────────────────────────────────────

    private static string Base64UrlEncode(byte[] bytes)
    {
        return Convert.ToBase64String(bytes)
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
    }

    private static string DecodeBase64Url(string base64Url)
    {
        string padded = base64Url
            .Replace('-', '+')
            .Replace('_', '/');

        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }

        return Encoding.UTF8.GetString(Convert.FromBase64String(padded));
    }
}

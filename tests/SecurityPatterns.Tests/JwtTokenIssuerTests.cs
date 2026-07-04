using System.IdentityModel.Tokens.Jwt;
using FluentAssertions;
using SecurityPatterns.VerifiableToken.Implementations;
using Xunit;

namespace SecurityPatterns.Tests;

public class JwtTokenIssuerTests
{
    private const string ValidKeyBase64 = "YXBpLXNlY3VyaXR5LXBhdHRlcm5zLXNlY3JldC1rZXktMjAyNg==";
    private const string Issuer = "TestIssuer";
    private const string Audience = "TestAudience";

    [Fact]
    public void GenerateToken_ShouldProduceValidJwt_WithExpectedClaimsAndExpiry()
    {
        // Arrange
        var issuer = new JwtTokenIssuer(ValidKeyBase64, Issuer, Audience);
        var claims = new Dictionary<string, string>
        {
            ["role"] = "Admin",
            ["scope"] = "read write"
        };
        var lifetime = TimeSpan.FromMinutes(30);

        // Act
        var result = issuer.GenerateToken("usr-001", "moein", claims, lifetime);

        // Assert — Token string is not null or empty
        result.Token.Should().NotBeNullOrWhiteSpace("a valid token must be produced");

        // Assert — TokenId is a valid non-empty GUID string
        result.TokenId.Should().NotBeNullOrWhiteSpace("every token must have a unique identifier");
        Guid.TryParse(result.TokenId, out _).Should().BeTrue("TokenId must be a valid GUID");

        // Assert — ExpiresAt is approximately now + lifetime (within 2 seconds tolerance)
        var expectedExpiry = DateTime.UtcNow.Add(lifetime);
        result.ExpiresAt.Should().BeCloseTo(expectedExpiry, TimeSpan.FromSeconds(2),
            "ExpiresAt should equal the current UTC time plus the requested lifetime");

        // Assert — Token can be parsed structurally by JwtSecurityTokenHandler
        var handler = new JwtSecurityTokenHandler();
        Action parseAction = () => handler.ReadJwtToken(result.Token);
        parseAction.Should().NotThrow("the token must be a structurally valid JWT");
    }

    [Fact]
    public void GenerateToken_ShouldProduceUniqueTokenIds_WhenCalledMultipleTimes()
    {
        // Arrange
        var issuer = new JwtTokenIssuer(ValidKeyBase64, Issuer, Audience);
        var claims = new Dictionary<string, string>();

        // Act
        var result1 = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(5));
        var result2 = issuer.GenerateToken("usr-001", "moein", claims, TimeSpan.FromMinutes(5));

        // Assert — Each token must have a unique TokenId (GUID v4 collision is astronomically unlikely)
        result1.TokenId.Should().NotBe(result2.TokenId,
            "each issuance must produce a unique token identifier for revocation tracking");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrowArgumentException_WhenSecretKeyIsNullOrWhiteSpace(string? badKey)
    {
        // Act
        Action act = () => new JwtTokenIssuer(badKey!, Issuer, Audience);

        // Assert
        act.Should().Throw<ArgumentException>("a null, empty, or whitespace key is invalid");
    }

    [Fact]
    public void Constructor_ShouldThrowArgumentException_WhenSecretKeyIsTooShort()
    {
        // Arrange — 16 bytes (128 bits), below the 256-bit minimum
        string shortKey = Convert.ToBase64String(new byte[16]);

        // Act
        Action act = () => new JwtTokenIssuer(shortKey, Issuer, Audience);

        // Assert
        act.Should().Throw<ArgumentException>()
            .WithMessage("*32 bytes*")
            .WithMessage("*CWE-326*",
                "the exception must reference the 256-bit minimum and CWE-326");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrowArgumentException_WhenIssuerIsNullOrWhiteSpace(string? badIssuer)
    {
        // Act
        Action act = () => new JwtTokenIssuer(ValidKeyBase64, badIssuer!, Audience);

        // Assert
        act.Should().Throw<ArgumentException>("issuer must not be null or empty");
    }

    [Theory]
    [InlineData(null)]
    [InlineData("")]
    [InlineData("   ")]
    public void Constructor_ShouldThrowArgumentException_WhenAudienceIsNullOrWhiteSpace(string? badAudience)
    {
        // Act
        Action act = () => new JwtTokenIssuer(ValidKeyBase64, Issuer, badAudience!);

        // Assert
        act.Should().Throw<ArgumentException>("audience must not be null or empty");
    }
}

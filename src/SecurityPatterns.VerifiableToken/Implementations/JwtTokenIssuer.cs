using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using SecurityPatterns.Core.Abstractions;

namespace SecurityPatterns.VerifiableToken.Implementations;

/// <summary>
/// Issues JSON Web Tokens (JWTs) signed with HMAC-SHA256, implementing the
/// "Verifiable Token-based Authentication" pattern.
/// </summary>
/// <remarks>
/// <para>
/// This implementation binds the token-signing pipeline to a symmetric key and
/// <see cref="SecurityAlgorithms.HmacSha256Signature"/> at construction time,
/// directly mitigating:
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>CWE-347 (Improper Verification of Cryptographic Signature):</strong>
///     The signing algorithm is explicitly specified and cannot be overridden by
///     caller-supplied parameters, ensuring every token is signed with a known,
///     strong algorithm.
///   </item>
///   <item>
///     <strong>CVE-2015-9235 (JWT "none" algorithm):</strong>
///     Because <see cref="SigningCredentials"/> are constructed from a
///     <see cref="SymmetricSecurityKey"/>, the <c>none</c> algorithm is never
///     an option in the token handler's algorithm selection.
///   </item>
/// </list>
/// <para>
/// The class is marked <c>sealed</c> to prevent inheritance-based tampering with
/// the cryptographic configuration. All state is set once in the constructor and
/// treated as immutable thereafter.
/// </para>
/// </remarks>
public sealed class JwtTokenIssuer : ITokenIssuer
{
    private const int MinimumKeyLengthBytes = 32; // 256 bits

    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly SigningCredentials _signingCredentials;
    private readonly string _issuer;
    private readonly string _audience;

    /// <summary>
    /// Initialises a new instance of the <see cref="JwtTokenIssuer"/> class with
    /// the cryptographic material and token metadata required for JWT issuance.
    /// </summary>
    /// <param name="secretKey">
    /// A Base64-encoded symmetric key used to sign tokens with HMAC-SHA256.
    /// The decoded key MUST be at least 32 bytes (256 bits) in length to satisfy
    /// NIST SP 800-131A minimum strength requirements for HMAC.
    /// </param>
    /// <param name="issuer">
    /// The issuer claim (<c>iss</c>) embedded in every issued token. This value
    /// identifies the authority that created the token and is verified by
    /// consumers to prevent token confusion attacks.
    /// </param>
    /// <param name="audience">
    /// The audience claim (<c>aud</c>) embedded in every issued token. This value
    /// restricts the token to a specific relying party, preventing cross-service
    /// token misuse.
    /// </param>
    /// <exception cref="ArgumentException">
    /// Thrown when <paramref name="secretKey"/> is <see langword="null"/>,
    /// empty, whitespace, or when the decoded key is shorter than 32 bytes.
    /// This validation enforces cryptographic strength at construction time,
    /// preventing weak-key vulnerabilities (CWE-326).
    /// </exception>
    /// <exception cref="FormatException">
    /// Thrown when <paramref name="secretKey"/> is not valid Base64.
    /// </exception>
    public JwtTokenIssuer(string secretKey, string issuer, string audience)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secretKey);
        ArgumentException.ThrowIfNullOrWhiteSpace(issuer);
        ArgumentException.ThrowIfNullOrWhiteSpace(audience);

        byte[] keyBytes = Convert.FromBase64String(secretKey);

        if (keyBytes.Length < MinimumKeyLengthBytes)
        {
            throw new ArgumentException(
                $"The decoded secret key must be at least {MinimumKeyLengthBytes} bytes " +
                $"({MinimumKeyLengthBytes * 8} bits) to meet HMAC-SHA256 strength requirements. " +
                $"The provided key is {keyBytes.Length} bytes ({keyBytes.Length * 8} bits). " +
                $"This validation mitigates CWE-326 (Inadequate Encryption Strength).",
                nameof(secretKey));
        }

        var securityKey = new SymmetricSecurityKey(keyBytes);
        _signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256Signature);
        _issuer = issuer;
        _audience = audience;

        _tokenHandler = new JwtSecurityTokenHandler();

        // Prevent the token handler from using default inbound/outbound mapping
        // that could inadvertently alter claim types.
        _tokenHandler.InboundClaimTypeMap.Clear();
        _tokenHandler.OutboundClaimTypeMap.Clear();
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// Each invocation produces a freshly signed JWT containing the supplied subject,
    /// username, and custom claims. A cryptographically random <c>jti</c> claim
    /// (GUID v4) is generated per token to enable revocation and prevent replay.
    /// </para>
    /// <para>
    /// The token is signed using HMAC-SHA256 with the symmetric key provided at
    /// construction. The resulting serialized string is self-contained and can be
    /// transmitted as a Bearer credential without additional wrapping.
    /// </para>
    /// <para>
    /// <strong>Security note:</strong> The <c>iat</c> and <c>nbf</c> claims are
    /// both set to the current UTC time, meaning the token is valid immediately
    /// upon issuance. The <c>exp</c> claim is set to <c>UtcNow + lifetime</c>.
    /// </para>
    /// </remarks>
    public TokenResult GenerateToken(
        string subjectId,
        string username,
        IDictionary<string, string> claims,
        TimeSpan lifetime)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(subjectId);
        ArgumentException.ThrowIfNullOrWhiteSpace(username);
        ArgumentNullException.ThrowIfNull(claims);

        string tokenId = Guid.NewGuid().ToString("D");
        DateTime utcNow = DateTime.UtcNow;
        DateTime expiresAt = utcNow.Add(lifetime);

        var claimList = new List<Claim>
        {
            new(JwtRegisteredClaimNames.Sub, subjectId),
            new(JwtRegisteredClaimNames.UniqueName, username),
            new(JwtRegisteredClaimNames.Jti, tokenId),
            new(JwtRegisteredClaimNames.Iat, new DateTimeOffset(utcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
            new(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(utcNow).ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
        };

        foreach (KeyValuePair<string, string> claim in claims)
        {
            claimList.Add(new Claim(claim.Key, claim.Value));
        }

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Issuer = _issuer,
            Audience = _audience,
            Subject = new ClaimsIdentity(claimList),
            NotBefore = utcNow,
            IssuedAt = utcNow,
            Expires = expiresAt,
            SigningCredentials = _signingCredentials,
        };

        JwtSecurityToken securityToken = _tokenHandler.CreateJwtSecurityToken(tokenDescriptor);
        string serializedToken = _tokenHandler.WriteToken(securityToken);

        return new TokenResult(serializedToken, tokenId, expiresAt);
    }
}

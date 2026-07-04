using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using SecurityPatterns.Core.Abstractions;

namespace SecurityPatterns.VerifiableToken.Implementations;

/// <summary>
/// Validates JSON Web Tokens (JWTs) signed with HMAC-SHA256, implementing the
/// "Verifiable Token-based Authentication" pattern.
/// </summary>
/// <remarks>
/// <para>
/// This implementation performs stateless, signature-based token verification.
/// No persistent store or session lookup is required — the token is self-contained
/// and its authenticity is established solely through cryptographic signature
/// verification.
/// </para>
/// <para>
/// The verification pipeline enforces the following security properties:
/// </para>
/// <list type="bullet">
///   <item>
///     <strong>CWE-347 (Improper Verification of Cryptographic Signature):</strong>
///     <c>ValidateIssuerSigningKey</c> is set to <see langword="true"/>, forcing
///     the handler to verify the HMAC-SHA256 signature before accepting any claims.
///   </item>
///   <item>
///     <strong>CVE-2015-9235 (JWT "none" algorithm):</strong>
///     <c>RequireSignedTokens</c> is <see langword="true"/> and
///     <c>ValidAlgorithms</c> is restricted to
///     <see cref="SecurityAlgorithms.HmacSha256Signature"/> only. Tokens with the
///     <c>none</c> algorithm or any non-HS256 algorithm are rejected outright.
///   </item>
///   <item>
///     <strong>CWE-287 (Improper Authentication):</strong>
///     Both issuer and audience are validated against expected values, preventing
///     token confusion and cross-service misuse.
///   </item>
///   <item>
///     <strong>CWE-613 (Insufficient Session Expiration):</strong>
///     Lifetime validation is enabled with <c>ClockSkew</c> set to
///     <see cref="TimeSpan.Zero"/>, ensuring expired tokens are rejected
///     immediately with no grace period.
///   </item>
/// </list>
/// <para>
/// The class is marked <c>sealed</c> to prevent inheritance-based tampering with
/// the validation configuration. All state is set once in the constructor and
/// treated as immutable thereafter.
/// </para>
/// </remarks>
public sealed class JwtTokenVerifier : ITokenVerifier
{
    private const int MinimumKeyLengthBytes = 32; // 256 bits

    private readonly JwtSecurityTokenHandler _tokenHandler;
    private readonly TokenValidationParameters _validationParameters;

    /// <summary>
    /// Initialises a new instance of the <see cref="JwtTokenVerifier"/> class with
    /// the cryptographic material and validation parameters required for JWT verification.
    /// </summary>
    /// <param name="secretKey">
    /// A Base64-encoded symmetric key used to verify token signatures with HMAC-SHA256.
    /// The decoded key MUST be at least 32 bytes (256 bits) in length to satisfy
    /// NIST SP 800-131A minimum strength requirements for HMAC.
    /// This key MUST correspond to the key used by <see cref="JwtTokenIssuer"/> to
    /// sign tokens.
    /// </param>
    /// <param name="issuer">
    /// The expected issuer claim (<c>iss</c>) that tokens MUST contain to be accepted.
    /// Tokens issued by a different authority are rejected to prevent token confusion
    /// attacks.
    /// </param>
    /// <param name="audience">
    /// The expected audience claim (<c>aud</c>) that tokens MUST contain to be accepted.
    /// Tokens intended for a different relying party are rejected to prevent
    /// cross-service token misuse.
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
    public JwtTokenVerifier(string secretKey, string issuer, string audience)
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

        _validationParameters = new TokenValidationParameters
        {
            // --- Signature validation (CWE-347) ---
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = securityKey,

            // --- Issuer & audience validation (CWE-287) ---
            ValidateIssuer = true,
            ValidIssuer = issuer,
            ValidateAudience = true,
            ValidAudience = audience,

            // --- Lifetime validation (CWE-613) ---
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero,

            // --- Algorithm whitelist (CVE-2015-9235) ---
            RequireSignedTokens = true,
            ValidAlgorithms = [SecurityAlgorithms.HmacSha256Signature],
        };

        _tokenHandler = new JwtSecurityTokenHandler();

        // Prevent the token handler from remapping claim types so that raw JWT
        // claim names (sub, jti, unique_name, etc.) are preserved in the
        // extracted claims dictionary.
        _tokenHandler.InboundClaimTypeMap.Clear();
        _tokenHandler.OutboundClaimTypeMap.Clear();
    }

    /// <inheritdoc />
    /// <remarks>
    /// <para>
    /// The method delegates to <see cref="JwtSecurityTokenHandler.ValidateToken(string, TokenValidationParameters, out SecurityToken?)"/>
    /// which performs cryptographic signature verification, issuer/audience matching,
    /// and lifetime checks in a single atomic operation.
    /// </para>
    /// <para>
    /// Any exception thrown by the handler (including <see cref="SecurityTokenException"/>,
    /// <see cref="ArgumentException"/>, and <see cref="FormatException"/>) is caught
    /// and translated to a <see langword="false"/> return value, ensuring that
    /// malformed or tampered tokens never cause unhandled exceptions in the host
    /// application.
    /// </para>
    /// <para>
    /// Upon successful validation, the <c>out</c> parameter
    /// <paramref name="extractedClaims"/> contains a dictionary of all claims
    /// present in the token, keyed by their original JWT claim types (e.g.,
    /// <c>sub</c>, <c>unique_name</c>, <c>jti</c>).
    /// </para>
    /// </remarks>
    public bool ValidateToken(string token, out IDictionary<string, string>? extractedClaims)
    {
        if (string.IsNullOrWhiteSpace(token))
        {
            extractedClaims = null;
            return false;
        }

        try
        {
            SecurityToken validatedToken;
            ClaimsPrincipal principal = _tokenHandler.ValidateToken(
                token,
                _validationParameters,
                out validatedToken);

            extractedClaims = new Dictionary<string, string>();

            IEnumerable<Claim> claims = principal.Claims;
            foreach (Claim claim in claims)
            {
                // Use the last value if duplicate claim types exist.
                extractedClaims[claim.Type] = claim.Value;
            }

            return true;
        }
        catch (SecurityTokenException)
        {
            // Signature mismatch, expired token, invalid issuer/audience, etc.
            extractedClaims = null;
            return false;
        }
        catch (ArgumentException)
        {
            // Malformed token structure.
            extractedClaims = null;
            return false;
        }
        catch (FormatException)
        {
            // Token is not valid Base64 or contains malformed segments.
            extractedClaims = null;
            return false;
        }
    }
}

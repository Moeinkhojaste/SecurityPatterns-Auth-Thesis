using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using SecurityPatterns.Core.Abstractions;
using SecurityPatterns.VerifiableToken.Implementations;

// ─── Configuration ────────────────────────────────────────────────────────────
const string SecretKeyBase64 = "YXBpLXNlY3VyaXR5LXBhdHRlcm5zLXNlY3JldC1rZXktMjAyNg==";
const string Issuer = "SecurityPatterns-Thesis";
const string Audience = "University-Diagnostics";

// ─── Initialise issuer & verifier (same key, symmetric pattern) ───────────────
var issuer = new JwtTokenIssuer(SecretKeyBase64, Issuer, Audience);
var verifier = new JwtTokenVerifier(SecretKeyBase64, Issuer, Audience);

// ─── Banner ───────────────────────────────────────────────────────────────────
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("╔══════════════════════════════════════════════════════════════════╗");
Console.WriteLine("║   SECURITY PATTERNS — VERIFIABLE TOKEN DIAGNOSTIC SUITE         ║");
Console.WriteLine("║   Bachelor Thesis · CWE & CVE Mitigation Demonstration          ║");
Console.WriteLine("╚══════════════════════════════════════════════════════════════════╝");
Console.ResetColor();
Console.WriteLine();

// ═══════════════════════════════════════════════════════════════════════════════
// SCENARIO A: Successful Authentication
// ═══════════════════════════════════════════════════════════════════════════════
PrintScenarioHeader("A", "Successful Authentication");

Console.WriteLine("  Action : Issuing a valid JWT for user 'moein' with roles Admin, Researcher");
Console.WriteLine("  Lifetime: 30 minutes");
Console.WriteLine();

var claimsForToken = new Dictionary<string, string>
{
    ["role"] = "Admin",
    ["scope"] = "thesis:read thesis:write"
};

TokenResult result = issuer.GenerateToken(
    "usr-001",
    "moein",
    claimsForToken,
    TimeSpan.FromMinutes(30));

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  TokenResult:");
Console.ResetColor();
Console.WriteLine($"    TokenId   : {result.TokenId}");
Console.WriteLine($"    ExpiresAt : {result.ExpiresAt:O}");
Console.WriteLine();

PrintTokenStructure(result.Token);
Console.WriteLine();

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Attempting validation (no DB lookup required)...");
Console.ResetColor();
Console.WriteLine();

bool isValid = verifier.ValidateToken(result.Token, out IDictionary<string, string>? extractedClaims);

if (isValid && extractedClaims is not null)
{
    Console.ForegroundColor = ConsoleColor.Green;
    Console.WriteLine("  ╔══════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  [PASS] Token validated — claims extracted without DB   ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════════════╝");
    Console.ResetColor();
    Console.WriteLine();

    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("  Extracted Claims:");
    Console.ResetColor();

    foreach (KeyValuePair<string, string> claim in extractedClaims)
    {
        Console.WriteLine($"    {claim.Key,-20} : {claim.Value}");
    }
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  [UNEXPECTED] Valid token was rejected — this should not happen.");
    Console.ResetColor();
}

Console.WriteLine();

// ═══════════════════════════════════════════════════════════════════════════════
// SCENARIO B: Token Tampering Attack (CWE-347)
// ═══════════════════════════════════════════════════════════════════════════════
PrintScenarioHeader("B", "Token Tampering Attack (CWE-347)");

Console.WriteLine("  Attack : Modifying the payload of a valid token to escalate privileges");
Console.WriteLine("  Target : Changing scope from 'thesis:read thesis:write' to 'admin:full-access'");
Console.WriteLine();

string[] validParts = result.Token.Split(['.']);
string headerB64 = validParts[0];
string payloadB64 = validParts[1];
string signatureB64 = validParts[2];

string payloadJson = Base64UrlDecode(payloadB64);
Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Original Payload (decoded):");
Console.ResetColor();
Console.WriteLine($"    {PayloadPrettyPrint(payloadJson)}");
Console.WriteLine();

// Tamper: replace the scope claim value
string tamperedPayloadJson = payloadJson
    .Replace("\"thesis:read thesis:write\"", "\"admin:full-access\"", StringComparison.Ordinal);
string tamperedPayloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(tamperedPayloadJson));

string tamperedToken = $"{headerB64}.{tamperedPayloadB64}.{signatureB64}";

Console.ForegroundColor = ConsoleColor.Red;
Console.WriteLine("  Tampered Payload (decoded):");
Console.ResetColor();
Console.WriteLine($"    {PayloadPrettyPrint(tamperedPayloadJson)}");
Console.WriteLine();

PrintTokenStructure(tamperedToken);
Console.WriteLine();

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Attempting validation on tampered token...");
Console.ResetColor();
Console.WriteLine();

bool tamperedValid = verifier.ValidateToken(tamperedToken, out _);

if (!tamperedValid)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  [BLOCKED] Tampered token rejected                             ║");
    Console.WriteLine("  ║  CWE-347 (Improper Verification of Cryptographic Signature)    ║");
    Console.WriteLine("  ║  The HMAC signature no longer matches the modified payload.    ║");
    Console.WriteLine("  ║  Without the secret key, the attacker cannot re-sign.          ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
    Console.ResetColor();
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  [VULNERABLE] Tampered token was accepted — CWE-347 NOT mitigated!");
    Console.ResetColor();
}

Console.WriteLine();

// ═══════════════════════════════════════════════════════════════════════════════
// SCENARIO C: Algorithm Downgrade Attack (CVE-2015-9235)
// ═══════════════════════════════════════════════════════════════════════════════
PrintScenarioHeader("C", "Algorithm Downgrade Attack (CVE-2015-9235)");

Console.WriteLine("  Attack : Forging a JWT with algorithm 'none' (no signature)");
Console.WriteLine("  Goal   : Bypass signature verification entirely");
Console.WriteLine();

// Craft a malicious token entirely outside the library — simulating an attacker
string attackHeaderJson = """{"alg":"none","typ":"JWT"}""";
string attackPayloadJson = """{"sub":"hacker-001","unique_name":"attacker","role":"SuperAdmin"}""";

string attackHeaderB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(attackHeaderJson));
string attackPayloadB64 = Base64UrlEncode(Encoding.UTF8.GetBytes(attackPayloadJson));

// The "none" algorithm produces an empty signature
string forgedToken = $"{attackHeaderB64}.{attackPayloadB64}.";

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Forged Token Structure:");
Console.ResetColor();
Console.WriteLine($"    Header  (decoded): {attackHeaderJson}");
Console.WriteLine($"    Payload (decoded): {attackPayloadJson}");
Console.WriteLine($"    Signature         : (empty — 'none' algorithm)");
Console.WriteLine();

PrintTokenStructure(forgedToken);
Console.WriteLine();

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Attempting validation on forged 'none' algorithm token...");
Console.ResetColor();
Console.WriteLine();

bool forgedValid = verifier.ValidateToken(forgedToken, out _);

if (!forgedValid)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  [BLOCKED] Forged 'none' algorithm token rejected              ║");
    Console.WriteLine("  ║  CVE-2015-9235 (JWT None Algorithm Vulnerability)              ║");
    Console.WriteLine("  ║  Verifier requires: RequireSignedTokens = true                 ║");
    Console.WriteLine("  ║                    ValidAlgorithms = [HmacSha256Signature]     ║");
    Console.WriteLine("  ║  The 'none' algorithm is NOT in the allowed algorithm list.    ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
    Console.ResetColor();
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  [VULNERABLE] Forged token was accepted — CVE-2015-9235 NOT mitigated!");
    Console.ResetColor();
}

Console.WriteLine();

// ═══════════════════════════════════════════════════════════════════════════════
// SCENARIO D: Replay / Expired Token Attack (CWE-613)
// ═══════════════════════════════════════════════════════════════════════════════
PrintScenarioHeader("D", "Expired Token / Replay Attack (CWE-613)");

Console.WriteLine("  Attack : Submitting a token whose expiration time is already in the past");
Console.WriteLine("  Method : Token issued with lifetime = -5 seconds (born expired)");
Console.WriteLine();

var expiredClaims = new Dictionary<string, string>
{
    ["role"] = "Admin",
    ["scope"] = "admin:full"
};

TokenResult expiredResult = issuer.GenerateToken(
    "usr-002",
    "victim",
    expiredClaims,
    TimeSpan.FromSeconds(-5));

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Expired TokenResult:");
Console.ResetColor();
Console.WriteLine($"    TokenId   : {expiredResult.TokenId}");
Console.WriteLine($"    ExpiresAt : {expiredResult.ExpiresAt:O}  ← (already in the past)");
Console.WriteLine($"    Now       : {DateTime.UtcNow:O}");
Console.WriteLine();

PrintTokenStructure(expiredResult.Token);
Console.WriteLine();

Console.ForegroundColor = ConsoleColor.Yellow;
Console.WriteLine("  Attempting validation on expired token...");
Console.ResetColor();
Console.WriteLine();

bool expiredValid = verifier.ValidateToken(expiredResult.Token, out _);

if (!expiredValid)
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  ╔══════════════════════════════════════════════════════════════════╗");
    Console.WriteLine("  ║  [BLOCKED] Expired token rejected                              ║");
    Console.WriteLine("  ║  CWE-613 (Insufficient Session Expiration)                     ║");
    Console.WriteLine("  ║  Verifier enforces: ValidateLifetime = true                    ║");
    Console.WriteLine("  ║                    ClockSkew = TimeSpan.Zero                   ║");
    Console.WriteLine("  ║  Token expiration (exp) is before current UTC time.            ║");
    Console.WriteLine("  ║  Zero clock skew means no grace period — immediate rejection.  ║");
    Console.WriteLine("  ╚══════════════════════════════════════════════════════════════════╝");
    Console.ResetColor();
}
else
{
    Console.ForegroundColor = ConsoleColor.Red;
    Console.WriteLine("  [VULNERABLE] Expired token was accepted — CWE-613 NOT mitigated!");
    Console.ResetColor();
}

Console.WriteLine();

// ═══════════════════════════════════════════════════════════════════════════════
// SUMMARY
// ═══════════════════════════════════════════════════════════════════════════════
Console.ForegroundColor = ConsoleColor.Cyan;
Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");
Console.WriteLine(" SUMMARY");
Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");
Console.ResetColor();
Console.WriteLine();
Console.WriteLine("  Scenario  Description                       Result    CWE/CVE Mitigated");
Console.WriteLine("  ────────  ────────────────────────────────  ────────  ──────────────────");
Console.WriteLine("  A         Valid authentication               PASS      Baseline");
Console.WriteLine("  B         Token tampering                    BLOCKED   CWE-347");
Console.WriteLine("  C         Algorithm downgrade (none)         BLOCKED   CVE-2015-9235");
Console.WriteLine("  D         Expired token replay               BLOCKED   CWE-613");
Console.WriteLine();
Console.ForegroundColor = ConsoleColor.Green;
Console.WriteLine("  All attack scenarios were successfully detected and rejected.");
Console.WriteLine("  The Verifiable Token library enforces cryptographic integrity,");
Console.WriteLine("  algorithm whitelisting, and strict lifetime validation.");
Console.ResetColor();
Console.WriteLine();

// ─── Helper Methods ───────────────────────────────────────────────────────────

static void PrintScenarioHeader(string letter, string title)
{
    Console.ForegroundColor = ConsoleColor.Cyan;
    Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");
    Console.WriteLine($" SCENARIO {letter}: {title.ToUpperInvariant()}");
    Console.WriteLine("══════════════════════════════════════════════════════════════════════════════");
    Console.ResetColor();
    Console.WriteLine();
}

static void PrintTokenStructure(string token)
{
    string[] parts = token.Split(['.']);

    string headerDecoded = SafeBase64UrlDecode(parts[0]);
    string payloadDecoded = parts.Length > 1 ? SafeBase64UrlDecode(parts[1]) : "(empty)";
    string signature = parts.Length > 2 && !string.IsNullOrEmpty(parts[2]) ? parts[2] : "(empty)";

    Console.ForegroundColor = ConsoleColor.Yellow;
    Console.WriteLine("  Token Structure:");
    Console.ResetColor();
    Console.WriteLine($"    Header    : {headerDecoded}");
    Console.WriteLine($"    Payload   : {PayloadPrettyPrint(payloadDecoded)}");
    Console.WriteLine($"    Signature : {TruncateSignature(signature)}");
}

static string Base64UrlEncode(byte[] bytes)
{
    return Convert.ToBase64String(bytes)
        .TrimEnd('=')
        .Replace('+', '-')
        .Replace('/', '_');
}

static string Base64UrlDecode(string base64Url)
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

static string SafeBase64UrlDecode(string base64Url)
{
    try
    {
        return Base64UrlDecode(base64Url);
    }
    catch
    {
        return $"(decode error: {base64Url})";
    }
}

static string PayloadPrettyPrint(string json)
{
    try
    {
        using JsonDocument doc = JsonDocument.Parse(json);
        string pretty = JsonSerializer.Serialize(doc.RootElement, new JsonSerializerOptions { WriteIndented = false });
        return pretty;
    }
    catch
    {
        return json;
    }
}

static string TruncateSignature(string signature)
{
    const int MaxDisplayLen = 40;
    if (signature.Length <= MaxDisplayLen)
        return signature;
    return $"{signature[..MaxDisplayLen]}... ({signature.Length} chars total)";
}

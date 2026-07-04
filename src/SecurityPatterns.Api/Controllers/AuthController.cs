using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using SecurityPatterns.Application.Interfaces;
using SecurityPatterns.Application.Models;

namespace SecurityPatterns.Api.Controllers;

[ApiController]
[Route("api/auth")]
[Produces("application/json")]
public sealed class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    /// <summary>
    /// Authenticates a user and returns a JWT Bearer token.
    /// </summary>
    /// <remarks>
    /// Demo credentials:
    /// - moein / Password123! (role: Admin)
    /// - admin / Admin456! (role: SuperAdmin)
    /// </remarks>
    /// <param name="request">The login credentials.</param>
    /// <returns>A JWT Bearer token response.</returns>
    /// <response code="200">Returns the newly created token.</response>
    /// <response code="401">If the credentials are invalid.</response>
    [HttpPost("token")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetToken([FromBody] LoginRequest request)
    {
        TokenResponse? response = _authService.Authenticate(request);

        if (response is null)
        {
            return Unauthorized(new { error = "Invalid username or password." });
        }

        return Ok(response);
    }

    /// <summary>
    /// Returns the authenticated user's profile and claims from the JWT token.
    /// Requires a valid Bearer token in the Authorization header.
    /// </summary>
    [HttpGet("profile")]
    [Authorize]
    [ProducesResponseType(typeof(ProfileResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public IActionResult GetProfile()
    {
        IDictionary<string, string> claims = User.Claims.ToDictionary(c => c.Type, c => c.Value);
        ProfileResponse profile = _authService.GetProfile(claims);
        return Ok(profile);
    }
}

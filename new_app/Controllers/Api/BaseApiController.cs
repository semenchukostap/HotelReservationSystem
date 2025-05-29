using System.Net;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace HotelReservationSystem.Controllers.Api;

/// <summary>
/// Base API controller that provides common functionality for all API controllers
/// </summary>
[ApiController]
[Route("api/v{version:apiVersion}/[controller]")]
[Produces("application/json")]
[ApiVersion("1.0")]
public abstract class BaseApiController : ControllerBase
{
    private readonly ILogger<BaseApiController> _logger;

    protected BaseApiController(ILogger<BaseApiController> logger)
    {
        _logger = logger;
    }

    /// <summary>
    /// Handles exceptions in a standardized way across all API controllers
    /// </summary>
    /// <param name="ex">The exception to handle</param>
    /// <param name="includeDetails">Whether to include exception details in the response (default: false)</param>
    /// <returns>A standardized error response</returns>
    protected ActionResult HandleException(Exception ex, bool includeDetails = false)
    {
        _logger.LogError(ex, "An error occurred processing the request");

        var error = new
        {
            Message = "An error occurred processing your request",
            Details = includeDetails ? ex.Message : null,
            StatusCode = HttpStatusCode.InternalServerError
        };

        return StatusCode((int)HttpStatusCode.InternalServerError, error);
    }

    /// <summary>
    /// Creates a standardized validation error response
    /// </summary>
    /// <param name="modelState">The ModelState containing validation errors</param>
    /// <returns>A Bad Request response with validation errors</returns>
    protected ActionResult HandleValidationError(ModelStateDictionary modelState)
    {
        var errors = modelState
            .Where(e => e.Value?.Errors.Count > 0)
            .ToDictionary(
                kvp => kvp.Key,
                kvp => kvp.Value?.Errors.Select(e => e.ErrorMessage).ToArray()
            );

        var error = new
        {
            Message = "Validation failed",
            Errors = errors,
            StatusCode = HttpStatusCode.BadRequest
        };

        return BadRequest(error);
    }

    /// <summary>
    /// Creates a standardized success response
    /// </summary>
    /// <param name="data">The data to return</param>
    /// <param name="statusCode">The HTTP status code (default: 200 OK)</param>
    /// <returns>An action result with the provided data and status code</returns>
    protected ActionResult Success<T>(T data, HttpStatusCode statusCode = HttpStatusCode.OK)
    {
        var response = new
        {
            Data = data,
            StatusCode = statusCode
        };

        return StatusCode((int)statusCode, response);
    }

    /// <summary>
    /// Creates a standardized not found response
    /// </summary>
    /// <param name="message">Custom not found message</param>
    /// <returns>A NotFound response with the specified message</returns>
    protected ActionResult NotFoundResponse(string message = "Resource not found")
    {
        var error = new
        {
            Message = message,
            StatusCode = HttpStatusCode.NotFound
        };

        return NotFound(error);
    }

    /// <summary>
    /// Logs and creates a standardized response for unauthorized access
    /// </summary>
    /// <param name="message">Custom unauthorized message</param>
    /// <returns>An Unauthorized response with the specified message</returns>
    protected ActionResult UnauthorizedResponse(string message = "Unauthorized access")
    {
        _logger.LogWarning("Unauthorized access attempt");

        var error = new
        {
            Message = message,
            StatusCode = HttpStatusCode.Unauthorized
        };

        return Unauthorized(error);
    }

    /// <summary>
    /// Creates a standardized response for forbidden access
    /// </summary>
    /// <param name="message">Custom forbidden message</param>
    /// <returns>A Forbidden response with the specified message</returns>
    protected ActionResult ForbiddenResponse(string message = "Access forbidden")
    {
        var error = new
        {
            Message = message,
            StatusCode = HttpStatusCode.Forbidden
        };

        return StatusCode((int)HttpStatusCode.Forbidden, error);
    }
}
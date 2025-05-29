using Microsoft.AspNetCore.Mvc;
using HotelReservationSystem.Web.Core;

namespace HotelReservationSystem.Web.Controllers;

/// <summary>
/// Base API controller that provides common functionality for all API controllers
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public abstract class BaseApiController : ControllerBase
{
    /// <summary>
    /// Handles the result of an operation and returns appropriate IActionResult
    /// </summary>
    /// <typeparam name="T">Type of the result value</typeparam>
    /// <param name="result">Result object containing operation outcome</param>
    /// <returns>IActionResult based on the operation result</returns>
    protected IActionResult HandleResult<T>(Result<T> result)
    {
        if (result == null) 
            return NotFound();
            
        if (result.IsSuccess && result.Value != null)
            return Ok(result.Value);
            
        if (result.IsSuccess && result.Value == null)
            return NotFound();
            
        return BadRequest(new ProblemDetails
        {
            Title = "Operation Failed",
            Detail = result.Error,
            Status = StatusCodes.Status400BadRequest
        });
    }

    /// <summary>
    /// Creates a successful result with the specified value
    /// </summary>
    /// <typeparam name="T">Type of the result value</typeparam>
    /// <param name="value">Value to return</param>
    /// <returns>Success result containing the value</returns>
    protected static Result<T> Success<T>(T value) => Result<T>.Success(value);

    /// <summary>
    /// Creates a failure result with the specified error message
    /// </summary>
    /// <typeparam name="T">Type of the result value</typeparam>
    /// <param name="error">Error message</param>
    /// <returns>Failure result containing the error message</returns>
    protected static Result<T> Failure<T>(string error) => Result<T>.Failure(error);
}
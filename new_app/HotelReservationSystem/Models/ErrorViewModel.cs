namespace HotelReservationSystem.Models;

/// <summary>
/// Represents a view model for error handling and display in the application.
/// </summary>
public sealed class ErrorViewModel
{
    /// <summary>
    /// Gets or sets the request identifier associated with the error.
    /// </summary>
    /// <value>The unique identifier for the request that generated the error.</value>
    public string? RequestId { get; init; }

    /// <summary>
    /// Gets a value indicating whether the request identifier should be displayed.
    /// </summary>
    /// <value>
    /// <c>true</c> if the request identifier should be shown; otherwise, <c>false</c>.
    /// </value>
    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
}
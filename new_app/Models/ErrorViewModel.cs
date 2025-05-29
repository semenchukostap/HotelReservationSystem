namespace HotelReservationSystem.Models;

public class ErrorViewModel
{
    /// <summary>
    /// Gets or sets the request identifier.
    /// </summary>
    public string? RequestId { get; set; }

    /// <summary>
    /// Gets a value indicating whether the request identifier should be shown.
    /// </summary>
    public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

    /// <summary>
    /// Gets or sets the error message.
    /// </summary>
    public string? ErrorMessage { get; set; }

    /// <summary>
    /// Gets or sets the error code.
    /// </summary>
    public int? StatusCode { get; set; }

    /// <summary>
    /// Gets or sets a value indicating whether this is a development environment.
    /// </summary>
    public bool IsDevelopmentEnvironment { get; set; }
}
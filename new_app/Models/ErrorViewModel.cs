using System;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Model for displaying error information in ASP.NET Core.
    /// Used by the Error.cshtml view to show error details to the user.
    /// </summary>
    public class ErrorViewModel
    {
        /// <summary>
        /// Gets or sets the request identifier.
        /// This helps to correlate errors with specific requests in logs.
        /// </summary>
        public string? RequestId { get; set; }

        /// <summary>
        /// Gets a value indicating whether the request ID should be shown to the user.
        /// Only shows the request ID if it's not null or empty.
        /// </summary>
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);

        /// <summary>
        /// Gets or sets the exception message.
        /// This property is populated in development environment to show detailed error information.
        /// </summary>
        public string? ExceptionMessage { get; set; }

        /// <summary>
        /// Gets or sets the exception stack trace.
        /// This property is populated only in development environment.
        /// </summary>
        public string? StackTrace { get; set; }

        /// <summary>
        /// Gets or sets a value indicating whether to show the full exception details.
        /// This should be true only in development environment.
        /// </summary>
        public bool ShowExceptionDetails { get; set; }
    }
}
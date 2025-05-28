using System;

namespace new_app.Models
{
    /// <summary>
    /// ViewModel used for displaying error information in ASP.NET Core MVC
    /// </summary>
    public class ErrorViewModel
    {
        /// <summary>
        /// The ID of the request that caused the error
        /// </summary>
        public string RequestId { get; set; }

        /// <summary>
        /// Indicates whether the request ID should be displayed to the user
        /// </summary>
        public bool ShowRequestId => !string.IsNullOrEmpty(RequestId);
        
        /// <summary>
        /// The error message to display
        /// </summary>
        public string ErrorMessage { get; set; }
        
        /// <summary>
        /// HTTP status code associated with the error
        /// </summary>
        public int? StatusCode { get; set; }
        
        /// <summary>
        /// Exception details (only shown in development environment)
        /// </summary>
        public Exception Exception { get; set; }
    }
}
namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Defines constants for role names used in the application's authorization system.
    /// These are used with ASP.NET Core Identity to manage access control.
    /// </summary>
    public static class RoleName
    {
        /// <summary>
        /// Role for users who can manage hotel information and settings in the system.
        /// </summary>
        public const string CanManageHotels = "CanManageHotels";
        
        /// <summary>
        /// Role for system administrators with full access to all features.
        /// </summary>
        public const string Administrator = "Administrator";
        
        /// <summary>
        /// Role for hotel staff members with limited management capabilities.
        /// </summary>
        public const string Staff = "Staff";
        
        /// <summary>
        /// Role for registered customers who can make reservations.
        /// </summary>
        public const string Customer = "Customer";
    }
}
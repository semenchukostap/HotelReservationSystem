namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Static class containing role name constants for authorization throughout the application
    /// </summary>
    public static class RoleName
    {
        /// <summary>
        /// Role that grants permission to manage hotels, customers, and orders
        /// </summary>
        public const string CanManageHotels = "CanManageHotels";

        /// <summary>
        /// Role that grants administrative privileges across the entire application
        /// </summary>
        public const string Admin = "Admin";
    }
}
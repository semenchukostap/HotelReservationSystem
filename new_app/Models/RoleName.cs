namespace HotelReservationSystem.Models;

/// <summary>
/// Static class that defines role constants used for authorization throughout the application.
/// </summary>
public static class RoleName
{
    /// <summary>
    /// Role that grants permissions to manage hotel data (create, update, delete).
    /// </summary>
    public const string CanManageHotels = "CanManageHotels";
    
    /// <summary>
    /// Role that grants administrative permissions throughout the application.
    /// Users with this role have full access to all system features.
    /// </summary>
    public const string Admin = "Admin";
    
    /// <summary>
    /// Role that grants read-only access to hotel data.
    /// </summary>
    public const string Viewer = "Viewer";
}

namespace HotelReservationSystem.Models;

public static class RoleConstants
{
    public const string Admin = "Admin";
    public const string HotelManager = "HotelManager";
    public const string CanManageHotels = "CanManageHotels";
    public const string Guest = "Guest";
    public const string Receptionist = "Receptionist";
    public const string MaintenanceStaff = "MaintenanceStaff";
    
    // Policy names
    public const string RequireAdmin = "RequireAdmin";
    public const string RequireHotelManager = "RequireHotelManager";
    public const string CanManageReservations = "CanManageReservations";
    public const string CanViewHotelDetails = "CanViewHotelDetails";
    public const string CanEditHotelDetails = "CanEditHotelDetails";
    public const string CanManageRooms = "CanManageRooms";
    public const string CanViewReports = "CanViewReports";
}
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Services
{
    public interface IJwtTokenService
    {
        string GenerateToken(ApplicationUser user);
    }
}
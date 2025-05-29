using System.Security.Claims;
using System.Threading.Tasks;
using HotelReservationSystem.Models;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.Services.Identity
{
    /// <summary>
    /// Interface for creating a ClaimsPrincipal from an ApplicationUser
    /// </summary>
    public interface IUserClaimsPrincipalFactory<TUser> where TUser : ApplicationUser
    {
        /// <summary>
        /// Creates a ClaimsPrincipal from an ApplicationUser
        /// </summary>
        /// <param name="user">The user to create the ClaimsPrincipal from</param>
        /// <returns>The ClaimsPrincipal for the specified user</returns>
        Task<ClaimsPrincipal> CreateAsync(TUser user);
    }
}
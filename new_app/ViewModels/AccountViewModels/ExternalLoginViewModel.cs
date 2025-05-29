using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;

namespace HotelReservationSystem.ViewModels
{
    public class ExternalLoginViewModel
    {
        public string? LoginProvider { get; set; }
        public string? ReturnUrl { get; set; }
        public string? Email { get; set; }
        public IList<AuthenticationScheme>? ExternalLogins { get; set; }
    }
}
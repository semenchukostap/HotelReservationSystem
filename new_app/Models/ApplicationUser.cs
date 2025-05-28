using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace new_app.Models
{
    /// <summary>
    /// Custom application user class that extends the ASP.NET Core Identity IdentityUser
    /// </summary>
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(20)]
        public string Phone { get; set; }
    }
}
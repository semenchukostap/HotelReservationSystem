using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace new_app.Models
{
    // Extending the default IdentityUser with custom properties
    public class ApplicationUser : IdentityUser
    {
        [Required]
        [MaxLength(20)]
        public string Phone { get; set; } = string.Empty;
    }
}
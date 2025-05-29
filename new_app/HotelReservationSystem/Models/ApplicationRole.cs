using Microsoft.AspNetCore.Identity;
using System;

namespace HotelReservationSystem.Models
{
    /// <summary>
    /// Custom identity role implementation that extends the default IdentityRole class
    /// to add additional properties like Description and tracking dates.
    /// </summary>
    public class ApplicationRole : IdentityRole
    {
        /// <summary>
        /// Default parameterless constructor required by Entity Framework Core
        /// </summary>
        public ApplicationRole() : base()
        {
            CreatedDate = DateTime.UtcNow;
        }

        /// <summary>
        /// Constructor that accepts role name parameter
        /// </summary>
        /// <param name="roleName">The name of the role</param>
        public ApplicationRole(string roleName) : base(roleName)
        {
            CreatedDate = DateTime.UtcNow;
        }

        /// <summary>
        /// Constructor that accepts role name and description parameters
        /// </summary>
        /// <param name="roleName">The name of the role</param>
        /// <param name="description">The description of the role</param>
        public ApplicationRole(string roleName, string description) : base(roleName)
        {
            Description = description;
            CreatedDate = DateTime.UtcNow;
        }

        /// <summary>
        /// Optional Description property for storing role description
        /// </summary>
        public string Description { get; set; }

        /// <summary>
        /// Property to track when role was created
        /// </summary>
        public DateTime CreatedDate { get; set; }

        /// <summary>
        /// Property to track when role was last modified
        /// </summary>
        public DateTime? ModifiedDate { get; set; }
    }
}
using System;
using System.ComponentModel.DataAnnotations;

namespace new_app.Models
{
    public class Customer
    {
        public int Id { get; set; }

        [Required]
        [MaxLength(255)]
        public string Name { get; set; }

        public DateTime? Birthdate { get; set; }
    }
}
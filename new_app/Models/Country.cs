using System.ComponentModel.DataAnnotations;

namespace new_app.Models
{
    public class Country
    {
        public int Id { get; set; }

        [Required]
        public string Name { get; set; }
    }
}
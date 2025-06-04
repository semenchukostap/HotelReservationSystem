namespace new_app.DTOs;

public class CountryDto
{
    public int Id { get; set; }
    public required string Name { get; set; } = string.Empty;
    
    public string? Description { get; set; }
    public string? IsoCode { get; set; }
    public string? FlagUrl { get; set; }
    
    public DateTimeOffset CreatedAt { get; set; } = DateTimeOffset.UtcNow;
    public DateTimeOffset? UpdatedAt { get; set; }
}
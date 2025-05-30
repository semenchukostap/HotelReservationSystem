using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public DbSet<Customer> Customers => Set<Customer>();
    public DbSet<Hotel> Hotels => Set<Hotel>();
    public DbSet<Country> Countries => Set<Country>();
    public DbSet<Order> Orders => Set<Order>();

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // Configure entity relationships and constraints here
        
        // Configure cascade delete behavior
        builder.Entity<Customer>()
            .HasMany(c => c.Orders)
            .WithOne(o => o.Customer)
            .OnDelete(DeleteBehavior.Restrict);
            
        builder.Entity<Hotel>()
            .HasMany(h => h.Orders)
            .WithOne(o => o.Hotel)
            .OnDelete(DeleteBehavior.Restrict);
            
        builder.Entity<Country>()
            .HasMany(c => c.Hotels)
            .WithOne(h => h.Country)
            .OnDelete(DeleteBehavior.Restrict);
    }
    
    protected override void ConfigureConventions(ModelConfigurationBuilder configurationBuilder)
    {
        base.ConfigureConventions(configurationBuilder);
        
        // Configure string properties to have a default max length
        configurationBuilder.Properties<string>()
            .AreUnicode()
            .HaveMaxLength(256);
            
        // Configure DateTime properties to use the date-time mapping
        configurationBuilder.Properties<DateTime>()
            .HaveColumnType("datetime2");
    }
}
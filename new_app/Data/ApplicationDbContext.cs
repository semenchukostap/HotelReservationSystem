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
        
        // Configure entity relationships
        builder.Entity<Order>()
            .HasOne(o => o.Customer)
            .WithMany(c => c.Orders)
            .HasForeignKey(o => o.CustomerId);
            
        builder.Entity<Order>()
            .HasOne(o => o.Hotel)
            .WithMany(h => h.Orders)
            .HasForeignKey(o => o.HotelId);
            
        builder.Entity<Hotel>()
            .HasOne(h => h.Country)
            .WithMany(c => c.Hotels)
            .HasForeignKey(h => h.CountryId);
    }
}
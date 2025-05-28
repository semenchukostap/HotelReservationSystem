using HotelReservationSystem.Core.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

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
        
        // Configure entity relationships and constraints
        builder.Entity<Hotel>()
            .HasOne(h => h.Country)
            .WithMany(c => c.Hotels)
            .HasForeignKey(h => h.CountryId);
            
        builder.Entity<Order>()
            .HasOne(o => o.Customer)
            .WithMany(c => c.Orders)
            .HasForeignKey(o => o.CustomerId);
            
        builder.Entity<Order>()
            .HasOne(o => o.Hotel)
            .WithMany()
            .HasForeignKey(o => o.HotelId);
            
        builder.Entity<Order>()
            .Property(o => o.FullPrice)
            .HasColumnType("decimal(18, 2)");
    }
}
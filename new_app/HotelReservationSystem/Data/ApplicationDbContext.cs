using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public DbSet<Customer> Customers { get; set; } = null!;
    public DbSet<Hotel> Hotels { get; set; } = null!;
    public DbSet<Country> Countries { get; set; } = null!;
    public DbSet<Order> Orders { get; set; } = null!;

    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }
    
    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        
        // Configure relationships and constraints here
        // Configure Order -> Customer relationship
        builder.Entity<Order>()
            .HasOne(o => o.Customer)
            .WithMany()
            .HasForeignKey(o => o.CustomerId)
            .OnDelete(DeleteBehavior.Cascade);
            
        // Configure Order -> Hotel relationship
        builder.Entity<Order>()
            .HasOne(o => o.Hotel)
            .WithMany()
            .HasForeignKey(o => o.HotelId)
            .OnDelete(DeleteBehavior.Cascade);
            
        // Configure Hotel -> Country relationship
        builder.Entity<Hotel>()
            .HasOne(h => h.Country)
            .WithMany()
            .HasForeignKey(h => h.CountryId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
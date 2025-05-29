using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using HotelReservationSystem.Models;

namespace HotelReservationSystem.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<Hotel> Hotels => Set<Hotel>();
    public DbSet<Country> Countries => Set<Country>();
    public DbSet<Order> Orders => Set<Order>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Hotel>()
            .HasOne(h => h.Country)
            .WithMany(c => c.Hotels)
            .HasForeignKey(h => h.CountryId);

        builder.Entity<Order>()
            .HasOne(o => o.User)
            .WithMany(u => u.Orders)
            .HasForeignKey(o => o.UserId);

        builder.Entity<Order>()
            .HasOne(o => o.Hotel)
            .WithMany(h => h.Hotels)
            .HasForeignKey(o => o.HotelId);
    }
}
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

    public DbSet<Hotel> Hotels { get; set; } = null!;
    public DbSet<Country> Countries { get; set; } = null!;
    public DbSet<Order> Orders { get; set; } = null!;

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<Hotel>(entity =>
        {
            entity.HasOne(h => h.Country)
                .WithMany(c => c.Hotels)
                .HasForeignKey(h => h.CountryId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.Property(h => h.Name)
                .IsRequired()
                .HasMaxLength(200);

            entity.Property(h => h.Description)
                .HasMaxLength(2000);

            entity.Property(h => h.PricePerNight)
                .HasPrecision(18, 2)
                .IsRequired();

            entity.Property(h => h.Rating)
                .HasPrecision(3, 1);
        });

        builder.Entity<Country>(entity =>
        {
            entity.Property(c => c.Name)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(c => c.Code)
                .IsRequired()
                .HasMaxLength(2);
        });

        builder.Entity<Order>(entity =>
        {
            entity.HasOne(o => o.User)
                .WithMany(u => u.Orders)
                .HasForeignKey(o => o.UserId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(o => o.Hotel)
                .WithMany(h => h.Hotels)
                .HasForeignKey(o => o.HotelId)
                .OnDelete(DeleteBehavior.Restrict);

            entity.Property(o => o.CheckInDate)
                .IsRequired();

            entity.Property(o => o.CheckOutDate)
                .IsRequired();

            entity.Property(o => o.TotalPrice)
                .HasPrecision(18, 2)
                .IsRequired();

            entity.Property(o => o.Status)
                .IsRequired()
                .HasMaxLength(50);
        });

        builder.Entity<ApplicationUser>(entity =>
        {
            entity.Property(u => u.FirstName)
                .IsRequired()
                .HasMaxLength(100);

            entity.Property(u => u.LastName)
                .IsRequired()
                .HasMaxLength(100);
        });
    }
}
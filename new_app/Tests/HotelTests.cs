using HotelReservationSystem.Models;
using Xunit;

namespace HotelReservationSystem.Tests;

public class HotelTests
{
    [Fact]
    public void Hotel_Properties_InitializeCorrectly()
    {
        // Arrange
        var hotel = new Hotel
        {
            Id = 1,
            Name = "Test Hotel",
            CountryId = 2,
            City = "Test City",
            Stars = 4,
            PricePerNight = 100.50,
            IsAllInclusive = true
        };

        // Assert
        Assert.Equal(1, hotel.Id);
        Assert.Equal("Test Hotel", hotel.Name);
        Assert.Equal(2, hotel.CountryId);
        Assert.Equal("Test City", hotel.City);
        Assert.Equal(4, hotel.Stars);
        Assert.Equal(100.50, hotel.PricePerNight);
        Assert.True(hotel.IsAllInclusive);
    }
}
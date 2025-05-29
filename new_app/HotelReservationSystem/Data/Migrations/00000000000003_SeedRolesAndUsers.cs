using Microsoft.EntityFrameworkCore.Migrations;
using System;

#nullable disable

namespace HotelReservationSystem.Data.Migrations
{
    public partial class SeedRolesAndUsers : Migration
    {
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            // Insert the CanManageHotels role
            migrationBuilder.InsertData(
                table: "AspNetRoles",
                columns: new[] { "Id", "Name", "NormalizedName", "ConcurrencyStamp" },
                values: new object[] { "56999692-99d2-4d6d-b661-c889ca08f2e0", "CanManageHotels", "CANMANAGEHOTELS", "9aeb4c43-f032-42e4-a23b-09d5080026f3" }
            );

            // Insert admin user with a predefined password hash compatible with ASP.NET Core Identity
            // The password hash below corresponds to "Admin@123" (you should change this in production)
            migrationBuilder.InsertData(
                table: "AspNetUsers",
                columns: new[] { "Id", "Email", "NormalizedEmail", "EmailConfirmed", "PasswordHash", "SecurityStamp", "ConcurrencyStamp", 
                                "PhoneNumber", "PhoneNumberConfirmed", "TwoFactorEnabled", "LockoutEnd", "LockoutEnabled", 
                                "AccessFailedCount", "UserName", "NormalizedUserName" },
                values: new object[] { "9aeb4c43-f032-42e4-a23b-09d5080026f3", "admin@admin.com", "ADMIN@ADMIN.COM", true, 
                                     "AQAAAAIAAYagAAAAEJ9OV5B2loQnoEhEVO9BgkQtYm7+B0qLa15AXX2lsFO3mID/hCSssCAY0s2o4IU7pQ==", 
                                     "d8465485-0a5e-4736-b605-1b9804f4d5f7", Guid.NewGuid().ToString(), 
                                     null, false, false, null, true, 0, "admin@admin.com", "ADMIN@ADMIN.COM" }
            );

            // Associate admin user with the CanManageHotels role
            migrationBuilder.InsertData(
                table: "AspNetUserRoles",
                columns: new[] { "UserId", "RoleId" },
                values: new object[] { "9aeb4c43-f032-42e4-a23b-09d5080026f3", "56999692-99d2-4d6d-b661-c889ca08f2e0" }
            );
        }

        protected override void Down(MigrationBuilder migrationBuilder)
        {
            // Remove data in reverse order of insertion
            
            // First remove the user-role association
            migrationBuilder.DeleteData(
                table: "AspNetUserRoles",
                keyColumns: new[] { "UserId", "RoleId" },
                keyValues: new object[] { "9aeb4c43-f032-42e4-a23b-09d5080026f3", "56999692-99d2-4d6d-b661-c889ca08f2e0" }
            );

            // Then remove the admin user
            migrationBuilder.DeleteData(
                table: "AspNetUsers",
                keyColumn: "Id",
                keyValue: "9aeb4c43-f032-42e4-a23b-09d5080026f3"
            );

            // Finally remove the role
            migrationBuilder.DeleteData(
                table: "AspNetRoles",
                keyColumn: "Id",
                keyValue: "56999692-99d2-4d6d-b661-c889ca08f2e0"
            );
        }
    }
}
using NUnit.Framework;
using HotelReservationSystem.Controllers;
using HotelReservationSystem.Models;
using Moq;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.Owin;
using System.Web.Mvc;
using System.Threading.Tasks;

namespace HotelReservationSystem.Tests.Controllers
{
    [TestFixture]
    public class AccountControllerTests
    {
        private Mock<ApplicationSignInManager> _signInManagerMock;
        private Mock<ApplicationUserManager> _userManagerMock;
        private AccountController _controller;

        [SetUp]
        public void SetUp()
        {
            _signInManagerMock = new Mock<ApplicationSignInManager>();
            _userManagerMock = new Mock<ApplicationUserManager>();
            _controller = new AccountController(_userManagerMock.Object, _signInManagerMock.Object);
        }

        [Test]
        public void Login_ReturnsViewResult()
        {
            // Act
            var result = _controller.Login("testUrl") as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("testUrl", result.ViewBag.ReturnUrl);
        }

        [Test]
        public async Task Register_ValidModel_RedirectsToHomeIndex()
        {
            // Arrange
            var model = new RegisterViewModel
            {
                Email = "test@test.com",
                Password = "Password123!",
                ConfirmPassword = "Password123!",
                Phone = "1234567890"
            };
            _userManagerMock.Setup(x => x.CreateAsync(It.IsAny<ApplicationUser>(), It.IsAny<string>())).ReturnsAsync(IdentityResult.Success);
            _signInManagerMock.Setup(x => x.SignInAsync(It.IsAny<ApplicationUser>(), false, false)).Returns(Task.CompletedTask);

            // Act
            var result = await _controller.Register(model) as RedirectToRouteResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual("Home", result.RouteValues["controller"]);
            Assert.AreEqual("Index", result.RouteValues["action"]);
        }

        [Test]
        public async Task Register_InvalidModel_ReturnsViewResult()
        {
            // Arrange
            var model = new RegisterViewModel();
            _controller.ModelState.AddModelError("Email", "Required");

            // Act
            var result = await _controller.Register(model) as ViewResult;

            // Assert
            Assert.IsNotNull(result);
            Assert.AreEqual(model, result.Model);
        }
    }
}
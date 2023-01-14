using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PermissionBasedAuthorization.ViewModels;

namespace PermissionBasedAuthorization.Controllers
{
    [Authorize(Roles = "SuperAdmin")]
    public class UsersController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<IdentityUser> _signInManager;

        public UsersController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }
        public async Task<IActionResult> Index()
        {
            var model = await _userManager.Users
                .Select(u => new UserViewModel
                {
                    userId = u.Id,
                    userName = u.UserName,
                    userEmail = u.Email,
                    Roles = _userManager.GetRolesAsync(u).Result.ToList()
                }).ToListAsync();

            return View(model);
        }

        public async Task<IActionResult> ManageRoles(string userId)
        {
            var user = await _userManager.FindByIdAsync(userId);

            if(user == null)
            {
                return NotFound();
            }

            var roles = await _roleManager.Roles.ToListAsync();

            var model = new UserRolesViewModel
            {
                userId = user.Id,
                userName = user.UserName,
                Roles = roles.Select( role => new CheckBoxViewModel
                {
                    DisplayValue = role.Name,
                    IsSelected = _userManager.IsInRoleAsync(user, role.Name).Result
                }).ToList()
            };

            return View(model);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManageRoles(UserRolesViewModel model)
        {
            var user = await _userManager.FindByIdAsync(model.userId);

            if (user == null) return NotFound();

            var userRoles = await _userManager.GetRolesAsync(user);

            //To Remove all userRoles
            await _userManager.RemoveFromRolesAsync(user, userRoles);

            //Get The new selcted Roles which came with this returning model
            var theNameOfNewSelectedRoles = model.Roles.Where(role => role.IsSelected).Select(role => role.DisplayValue).ToList();

            //Add the new Roles to this user
            await _userManager.AddToRolesAsync(user, theNameOfNewSelectedRoles);

            return RedirectToAction(nameof(Index));
        }

    }
}

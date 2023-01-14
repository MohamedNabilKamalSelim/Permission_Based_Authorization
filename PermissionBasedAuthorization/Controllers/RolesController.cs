using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PermissionBasedAuthorization.Constants;
using PermissionBasedAuthorization.ViewModels;
using System.Security.Claims;

namespace PermissionBasedAuthorization.Controllers
{
    [Authorize(Roles = "SuperAdmin")]
    public class RolesController : Controller
    {
        private readonly RoleManager<IdentityRole> _roleManager;

        public RolesController(RoleManager<IdentityRole> roleManager)
        {
            _roleManager = roleManager;
        }
        public async Task<IActionResult> Index()
        {
            var roles = await _roleManager.Roles.ToListAsync();

            return View(roles);
        }

        public async Task<IActionResult> Add(RoleFormViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View("Index", await _roleManager.Roles.ToListAsync());
            }

            if(await _roleManager.RoleExistsAsync(model.Name))
            {
                ModelState.AddModelError("Name", "Role is already exists!");

                return View("Index", await _roleManager.Roles.ToListAsync());
            }

            await _roleManager.CreateAsync(new IdentityRole(model.Name.Trim()));

            return RedirectToAction(nameof(Index));
        }


        public async Task<IActionResult> ManagePermissions(string roleId)
        {
            var role = await _roleManager.FindByIdAsync(roleId);

            if (role == null) return NotFound();

            var roleClaims = _roleManager.GetClaimsAsync(role).Result.Select(c => c.Value).ToList();

            var allClaims = Permissions.GenerateAllPermissions();

            var allPermissions = allClaims.Select(p => new CheckBoxViewModel { DisplayValue = p }).ToList();

            foreach(var permission in allPermissions)
            {
                if (roleClaims.Any(c => c == permission.DisplayValue))
                    permission.IsSelected = true;
            }

            var viewModel = new PermissionsFormViewModel
            {
                roleId = role.Id,
                roleName = role.Name,
                roleClaims = allPermissions
            };

            return View(viewModel);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ManagePermissions(PermissionsFormViewModel model)
        {
            var role = await _roleManager.FindByIdAsync(model.roleId);

            if (role == null) return NotFound();

            //Get all claims which already assigned to this role
            var roleClaims = await _roleManager.GetClaimsAsync(role);

            //Remover all claims from this role
            foreach (var claim in roleClaims)
            {
                await _roleManager.RemoveClaimAsync(role, claim);
            }

            //Get all selcted claims returned from view in model parameter 
            var selectedClaims = model.roleClaims.Where(c => c.IsSelected).ToList();

            //Add all selected Claims to this role
            foreach (var claim in selectedClaims)
            {
                await _roleManager.AddClaimAsync(role, new Claim("Permission", claim.DisplayValue));
            }

            return RedirectToAction(nameof(Index));
        }
    }
}

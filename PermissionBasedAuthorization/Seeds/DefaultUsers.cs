using Microsoft.AspNetCore.Identity;
using PermissionBasedAuthorization.Constants;
using System.Security.Claims;

namespace PermissionBasedAuthorization.Seeds
{
    public static class DefaultUsers
    {
        public static async Task SeedBasicUser(UserManager<IdentityUser> userManager)
        {
            var defaultBasicUser = new IdentityUser
            {
                UserName = "basic@test.com",
                Email = "basic@test.com",
                EmailConfirmed = true,
            };
            var user = await userManager.FindByEmailAsync(defaultBasicUser.Email);
            if (user == null)
            {
                await userManager.CreateAsync(defaultBasicUser, "P@ssword123");
                await userManager.AddToRoleAsync(defaultBasicUser, Roles.Basic.ToString());
            }
        }

        public static async Task SeedSuperAdmin(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            var defaultSuperAdmin = new IdentityUser
            {
                UserName = "super_admin@test.com",
                Email = "super_admin@test.com",
                EmailConfirmed = true
            };
            var user = await userManager.FindByEmailAsync(defaultSuperAdmin.Email);
            if(user == null)
            {
                await userManager.CreateAsync(defaultSuperAdmin, "P@ssword123");
                await userManager.AddToRolesAsync(defaultSuperAdmin, new List<string>
                {
                    Roles.SuperAdmin.ToString(),
                    Roles.Admin.ToString(),
                    Roles.Basic.ToString()
                });
            }
            await roleManager.SeedClaimsForSuperAdmin();
        }
        private static async Task SeedClaimsForSuperAdmin(this RoleManager<IdentityRole> roleManager)
        {
            var superAdminRole = await roleManager.FindByNameAsync(Roles.SuperAdmin.ToString());

            await roleManager.AddPermissionClaims(superAdminRole, "Products");
        }
        public static async Task AddPermissionClaims(this RoleManager<IdentityRole> roleManager, IdentityRole role, string module)
        {
            var allClaims = await roleManager.GetClaimsAsync(role);
            var allPermissions = Permissions.GeneratePermissionsList(module);

            foreach (var permission in allPermissions)
            {
                if(!allClaims.Any(c => c.Type == "Permission" && c.Value == permission))
                {
                    await roleManager.AddClaimAsync(role, new Claim("Permission", permission));
                }
            }

        }
    }
}

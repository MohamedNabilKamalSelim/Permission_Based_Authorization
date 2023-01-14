using Microsoft.AspNetCore.Authorization;

namespace PermissionBasedAuthorization.Filter
{
    public class PermissionAuthorizationHandler : AuthorizationHandler<PermissionRequirment>
    {
        public PermissionAuthorizationHandler()
        {

        }
        protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, PermissionRequirment requirement)
        {
            if (context.User == null) return;

            var canAccess = context.User.Claims.Any(c => c.Type == "Permission"
            && c.Value == requirement.Permission && c.Issuer == "LOCAL AUTHORITY");

            if (canAccess)
            {
                context.Succeed(requirement);
                return;
            }
        }
    }
}

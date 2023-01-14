namespace PermissionBasedAuthorization.ViewModels
{
    public class UserViewModel
    {
        public string userId { get; set; }
        public string userName { get; set; }
        public string userEmail { get; set; }
        public List<string> Roles { get; set; }
    }
}

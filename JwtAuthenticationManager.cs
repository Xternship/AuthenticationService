using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace AuthenticationService
{
    public static class JwtAuthenticationManager
    {
        public const string JWT_TOKEN_KEY = "Xternship";
        public const int JWT_TOKEN_VALIDITY = 30;
        public static AuthenticationResponse Authenticate(AuthenticationRequest authenticateRequest)
        {

            if (authenticateRequest.UserName == "admin" && authenticateRequest.Password == "admin")
            {
                return GenerateJwtToken(authenticateRequest.UserName, "Admin");
            }
            else if (authenticateRequest.UserName == "intern" && authenticateRequest.Password == "intern")
            {
                return GenerateJwtToken(authenticateRequest.UserName, "intern");
            }
            else if (authenticateRequest.UserName == "mentor" && authenticateRequest.Password == "mentor")
            {
                return GenerateJwtToken(authenticateRequest.UserName, "Mentor");
            }
            else if (authenticateRequest.UserName == "evaluator" && authenticateRequest.Password == "evaluator")
            {
                return GenerateJwtToken(authenticateRequest.UserName, "Evaluator");
            }
            else if (authenticateRequest.UserName == "management" && authenticateRequest.Password == "management")
            {
                return GenerateJwtToken(authenticateRequest.UserName, "Management");
            }
            return null;
        }

        private static AuthenticationResponse GenerateJwtToken(string username, string userRole)
        {
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var tokenKey = Encoding.ASCII.GetBytes(JWT_TOKEN_KEY);
            var tokenExpiryDateTime = DateTime.Now.AddMinutes(JWT_TOKEN_VALIDITY);
            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new List<Claim>
                    {
                         new Claim("username", username),
                         new Claim(ClaimTypes.Role, userRole),
                     }),
                Expires = tokenExpiryDateTime,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(tokenKey), SecurityAlgorithms.HmacSha256Signature)
            };
            var securityToken = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var token = jwtSecurityTokenHandler.WriteToken(securityToken);

            return new AuthenticationResponse
            {
                AccessToken = token,
                ExpriesIn = (int)tokenExpiryDateTime.Subtract(DateTime.Now).TotalSeconds
            };
        }

    }
}
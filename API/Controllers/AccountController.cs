using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace API.Controllers {
	[Route("api/[controller]")]
	[ApiController]
	public class AccountController : BaseApiController {
		private readonly DataContext _context;

		public AccountController(DataContext context) {
			_context = context;
		}

		[HttpPost("register")]
		public async Task<ActionResult<User>> Register(string username, string password) {
			using var hmac = new HMACSHA512();

			var user = new User() {
				UserName = username,
				PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password)),
				PasswordSalt = hmac.Key
			};

			_context.Users.Add(user);
			await _context.SaveChangesAsync();

			return user;
		}
	}
}

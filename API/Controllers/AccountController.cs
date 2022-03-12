using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
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
		public async Task<ActionResult<User>> Register(ViewModels.Input.RegisterDto registerDto) {

			if (await UserExistsAsync(registerDto.Username)) {
				return BadRequest("Username is taken");
			}

			using var hmac = new HMACSHA512();

			var user = new User() {
				UserName = registerDto.Username.ToLower(),
				PasswordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(registerDto.Password)),
				PasswordSalt = hmac.Key
			};

			_context.Users.Add(user);
			await _context.SaveChangesAsync();

			return user;
		}
		[HttpPost("login")]
		public async Task<ActionResult<User>> Login(ViewModels.Input.LoginDto loginDto) {
			var user = await _context.Users.SingleOrDefaultAsync(x => x.UserName == loginDto.Username.ToLower());

			if (null == user)
				return Unauthorized("Invalid user");

			using var hmac = new HMACSHA512(user.PasswordSalt);

			var passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(loginDto.Password));

			if (passwordHash.SequenceEqual(user.PasswordHash)) {
				return user;
			} else {
				return Unauthorized("Invalid password");
			}

		}

		private Task<bool> UserExistsAsync(string username) {
			return _context.Users.AnyAsync(x => x.UserName.ToLower() == username.ToLower());
		}
	}
}

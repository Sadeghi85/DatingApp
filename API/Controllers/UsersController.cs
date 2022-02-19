using API.Data;
using API.Entities;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace API.Controllers {
	[Route("api/[controller]")]
	[ApiController]
	public class UsersController : ControllerBase {
		private readonly DataContext _context;

		public UsersController(DataContext context) {
			_context = context;
		}

		[HttpGet]
		public async Task<ActionResult<IEnumerable<User>>> GetUsers() {
			var users = await _context.Users.ToListAsync();

			return users;
		}

		[HttpGet("{id}")]
		public async Task<ActionResult<User>> GetUser(int id) {
			
			var user = await _context.Users.FindAsync(id);

			return user;
		}
	}
}
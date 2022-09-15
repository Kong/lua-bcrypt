package = "bcrypt"
version = "2.4.0-1"

source = {
	url = "git+https://github.com/Kong/lua-bcrypt.git",
	tag = "2.4.0",
}

description = {
	summary = "A Lua wrapper for bcrypt",
	homepage = "http://github.com/Kong/lua-bcrypt",
	license = "ISC",
	maintainer = "Kong Inc.",
}

dependencies = {
	"lua >= 5.1",
}

build = {
	type = "builtin",
	modules = {
		bcrypt = {
			"src/main.c",
			"src/bcrypt.c",
			"src/blowfish.c",
			"src/ggentropy.c",
			"src/safebfuns.c",
		}
	},
}

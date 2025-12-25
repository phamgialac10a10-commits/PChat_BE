import { DatabaseModule  } from "./database/database.module";
import { RoleModule } from "./role/role.module";
import { UserModule } from "./user/user.module";
import { AuthModule } from "./auth/auth.module";


export const AppModules = [
    DatabaseModule,
    RoleModule,
    UserModule,
    AuthModule
]
import { DatabaseModule  } from "./database/database.module";
import { RoleModule } from "./role/role.module";
import { UserModule } from "./user/user.module";


export const AppModules = [
    DatabaseModule,
    RoleModule,
    UserModule,
]
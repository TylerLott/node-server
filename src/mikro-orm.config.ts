import { __prod__ } from "./constants"
import { Post } from "./entities/Post"
import { MikroORM } from "@mikro-orm/core"
import path from "path"
import { Users } from "./entities/User"

export default {
  migrations: {
    path: path.join(__dirname, "./migrations"),
    pattern: /^[\w-]+\d+\.[tj]s$/,
  },
  entities: [Post, Users],
  dbName: "blog-site",
  type: "postgresql",
  debug: __prod__,
  user: "postgres",
  password: "postgres",
} as Parameters<typeof MikroORM.init>[0]

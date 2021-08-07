import { MyContext } from "src/types"
import { Arg, Ctx, Field, Mutation, ObjectType, Resolver } from "type-graphql"
import argon2 from "argon2"
import { Users } from "../entities/User"

@ObjectType()
class FieldError {
  @Field()
  field: string

  @Field()
  message: string
}

@ObjectType()
class UserResponse {
  @Field(() => [FieldError], { nullable: true })
  errors?: FieldError[]

  @Field(() => Users, { nullable: true })
  user?: Users
}

@Resolver()
export class UserResolver {
  @Mutation(() => UserResponse)
  async register(
    @Arg("username") username: string,
    @Arg("password") password: string,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    if (username.length <= 2) {
      return {
        errors: [
          {
            field: "username",
            message: "username must be at least 2 characters",
          },
        ],
      }
    }
    if (password.length <= 4) {
      return {
        errors: [
          {
            field: "password",
            message: "password must be at least 4 characters",
          },
        ],
      }
    }
    const hashedPass = await argon2.hash(password)
    const user = em.create(Users, { username: username, password: hashedPass })
    try {
      await em.persistAndFlush(user)
    } catch (err) {
      if (err.code === "23505") {
        return {
          errors: [
            {
              field: "username",
              message: "username has already been taken",
            },
          ],
        }
      }
    }

    return { user }
  }
  @Mutation(() => UserResponse)
  async login(
    @Arg("username") username: string,
    @Arg("password") password: string,
    @Ctx() { em }: MyContext
  ): Promise<UserResponse> {
    const user = await em.findOne(Users, { username: username })
    if (!user) {
      return {
        errors: [
          {
            field: "username",
            message: "That username doesn't exist",
          },
        ],
      }
    }
    const valid = await argon2.verify(user.password, password)
    if (!valid) {
      return {
        errors: [
          {
            field: "password",
            message: "incorrect password",
          },
        ],
      }
    }
    return { user }
  }
}

import Elysia from "elysia";
import { prisma } from "../lib/prisma";
import { loginBodySchema, signupBodySchema } from "./schema";
import { authPlugin } from "./plugin";
import { ACCESS_TOKEN_EXP, REFRESH_TOKEN_EXP } from "./config/constant";
import { getExpTimestamp } from "./lib/util";

export const authRoutes = new Elysia({ prefix: "/api/auth" })
  .post(
    "/sign-in",
    async ({ body, jwt, cookie: { accessToken, refreshToken }, set }: any) => {
      // match user email
      const user = await prisma.user.findUnique({
        where: {
          email: body.email,
        },
        select: {
          id: true,
          email: true,
          password: true,
        },
      });

      if (!user) {
        set.status = "Bad Request";
        throw new Error(
          "The email address or password you entered is incorrect"
        );
      }

      // match password
      const matchPassword = await Bun.password.verify(
        body.password,
        user.password,
        "bcrypt"
      );

      if (!matchPassword) {
        set.status = "Bad Request";
        throw new Error(
          "The email address or password you entered is incorrect"
        );
      }

      // create access token
      const accessJWTToken = await jwt.sign({
        sub: user.id,
        exp: getExpTimestamp(ACCESS_TOKEN_EXP),
      });
      accessToken.set({
        value: accessJWTToken,
        httpOnly: true,
        maxAge: ACCESS_TOKEN_EXP,
        path: "/",
      });

      // create refrsh token
      const refreshJWTToken = await jwt.sign({
        sub: user.id,
        exp: getExpTimestamp(REFRESH_TOKEN_EXP),
      });
      refreshToken.set({
        value: refreshJWTToken,
        httpOnly: true,
        maxAge: REFRESH_TOKEN_EXP,
        path: "/",
      });

      // set user profile as online
      const updatedUser = await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          isOnline: true,
          refreshToken: refreshJWTToken,
        },
      });

      return {
        message: "Sign-in successfully",
        data: {
          user: updatedUser,
          accessToken: accessJWTToken,
          refreshToken: refreshJWTToken,
        },
      };
    },
    {
      body: loginBodySchema,
    }
  )
  .post(
    "/sign-up",
    async ({ body }: any) => {
      // hash password
      const password = await Bun.password.hash(body.password, {
        algorithm: "bcrypt",
        cost: 10,
      });

      const user = await prisma.user.create({
        data: {
          ...body,
          password,
        },
      });

      return {
        message: "Account created successfully",
        data: {
          user,
        },
      };
    },
    {
      body: signupBodySchema,
      error({ code, set, body }) {
        // handle duplicate email error throw by prisma
        // p2002 diplicate field error code
        if ((code as unknown) === "P2002") {
          set.status = "Conflict";
          return {
            name: "Error",
            message: `The email address provided ${body.email} already exists`,
          };
        }
      },
    }
  )
  .post(
    "/refresh",
    async ({ cookie: { accessToken, refreshToken }, jwt, set }: any) => {
      if (!refreshToken.value) {
        // handle error for refresh token in not available
        set.statu = "Unauthorized";
        throw new Error("Refresh token is missing");
      }

      // get refrsh token from cookie
      const jwtPayload = await jwt.verify(refreshToken.value);
      if (!jwtPayload) {
        // handle error for refresh token is tempted or incorrect
        set.status = "Forbidden";
        throw new Error("Refresh token is invalid");
      }

      // get user from refresh token
      const userId = jwtPayload.sub;

      // verify user exist or not
      const user = await prisma.user.findUnique({
        where: {
          id: userId,
        },
      });

      if (!user) {
        // handle error for user not found from the priovided refresh token
        set.status = "Forbidden";
        throw new Error("Refresh token is invalid");
      }

      // create new access token
      const accessJWTToken = await jwt.sign({
        sub: user.id,
        exp: getExpTimestamp(ACCESS_TOKEN_EXP),
      });
      accessToken.set({
        value: accessJWTToken,
        httpOnly: true,
        maxAge: ACCESS_TOKEN_EXP,
        path: "/",
      });

      // create new refresh token
      const refreshJWTToken = await jwt.sign({
        sub: user.id,
        exp: getExpTimestamp(REFRESH_TOKEN_EXP),
      });
      refreshToken.set({
        value: refreshJWTToken,
        httpOnly: true,
        maxAge: REFRESH_TOKEN_EXP,
        path: "/",
      });

      //   set refrsh token in db
      await prisma.user.update({
        where: {
          id: user.id,
        },
        data: {
          refreshToken: refreshJWTToken,
        },
      });

      return {
        message: "Access token generated successfully",
        data: {
          accessToken: accessJWTToken,
          refreshToken: refreshJWTToken,
        },
      };
    }
  )
  .use(authPlugin)
  .post("/logout", async ({ cookie: { accessToken, refreshToken }, user }) => {
    // remove refresh token and access token from cookies
    accessToken.remove();
    refreshToken.remove();

    // remove refresh token from db & set user onlie status to offline
    await prisma.user.update({
      where: {
        id: user.id,
      },
      data: {
        isOnline: false,
        refreshToken: null,
      },
    });
    return {
      message: "Logout successfully",
    };
  })
  .get("/me", ({ user }) => {
    return {
      message: "Fetch current user",
      data: {
        user,
      },
    };
  });

import { Elysia } from "elysia";
import { authRoutes } from "./route";
import swagger from "@elysiajs/swagger";

const app = new Elysia().use(swagger()).use(authRoutes).listen(3000);

console.log(
  `🦊 Elysia is running at ${app.server?.hostname}:${app.server?.port}`
);

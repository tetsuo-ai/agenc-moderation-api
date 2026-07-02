#!/usr/bin/env node
import { startServer } from "./server.js";

startServer().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exit(1);
});

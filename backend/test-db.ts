import "dotenv/config";
import { PrismaPg } from "@prisma/adapter-pg";
import { PrismaClient } from "./generated/prisma/client";

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL!,
});

const prisma = new PrismaClient({ adapter });

async function main() {
  await prisma.$connect();
  console.log("TrustVault Database Connected Successfully!");
  await prisma.$disconnect();
}

main().catch(async (error) => {
  console.error("Database connection failed:", error);
  await prisma.$disconnect();
  process.exit(1);
});
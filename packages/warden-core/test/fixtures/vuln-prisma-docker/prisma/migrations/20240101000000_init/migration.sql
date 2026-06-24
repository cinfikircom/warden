-- Bu migration KASITLI olarak yıkıcıdır (test fixture'ı).
CREATE TABLE "User" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    CONSTRAINT "User_pkey" PRIMARY KEY ("id")
);

-- Veri kaybına yol açan adımlar:
ALTER TABLE "User" DROP COLUMN "phone";
DROP TABLE "legacy_sessions";

CREATE TYPE "public"."project_kind" AS ENUM('application', 'library', 'image', 'host');--> statement-breakpoint
ALTER TABLE "projects" ADD COLUMN "kind" "project_kind" DEFAULT 'application' NOT NULL;
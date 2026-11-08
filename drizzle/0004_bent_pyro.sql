ALTER TABLE "packages" ADD COLUMN "source_repo" text;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "scorecard_score" real;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "scorecard_checks" jsonb;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "scorecard_checked_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "scorecard_error" text;
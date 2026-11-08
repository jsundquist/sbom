ALTER TABLE "packages" ADD COLUMN "latest_released_at" timestamp with time zone;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "deprecated" boolean DEFAULT false NOT NULL;--> statement-breakpoint
ALTER TABLE "packages" ADD COLUMN "deprecated_reason" text;
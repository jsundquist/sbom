CREATE TABLE "feed_syncs" (
	"name" text PRIMARY KEY NOT NULL,
	"synced_at" timestamp with time zone,
	"attempted_at" timestamp with time zone DEFAULT now() NOT NULL,
	"error" text
);
--> statement-breakpoint
CREATE TABLE "kev_entries" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"vendor" text,
	"product" text,
	"name" text,
	"date_added" date NOT NULL,
	"due_date" date,
	"known_ransomware_use" boolean DEFAULT false NOT NULL
);

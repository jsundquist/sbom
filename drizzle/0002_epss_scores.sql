CREATE TABLE "epss_scores" (
	"cve_id" text PRIMARY KEY NOT NULL,
	"score" real,
	"percentile" real,
	"model_date" date,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);

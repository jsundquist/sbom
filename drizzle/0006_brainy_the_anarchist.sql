CREATE TABLE "project_snapshots" (
	"id" serial PRIMARY KEY NOT NULL,
	"project_id" integer NOT NULL,
	"day" date NOT NULL,
	"components" integer NOT NULL,
	"vulnerable_components" integer NOT NULL,
	"vulnerabilities" integer NOT NULL,
	"critical" integer NOT NULL,
	"high" integer NOT NULL,
	"medium" integer NOT NULL,
	"low" integer NOT NULL,
	"unknown" integer NOT NULL,
	"outdated_components" integer NOT NULL,
	"outdated_major" integer NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "project_snapshots_project_day_unique" UNIQUE("project_id","day")
);
--> statement-breakpoint
ALTER TABLE "project_snapshots" ADD CONSTRAINT "project_snapshots_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;
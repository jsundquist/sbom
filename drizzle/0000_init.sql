CREATE TYPE "public"."severity" AS ENUM('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN');--> statement-breakpoint
CREATE TABLE "components" (
	"id" serial PRIMARY KEY NOT NULL,
	"sbom_id" integer NOT NULL,
	"name" text NOT NULL,
	"version" text,
	"purl" text,
	"ecosystem" text,
	"package_key" text,
	"type" text,
	"licenses" text,
	"supplier" text
);
--> statement-breakpoint
CREATE TABLE "package_versions" (
	"package_key" text NOT NULL,
	"version" text NOT NULL,
	"vulns_checked_at" timestamp with time zone,
	"vulns_error" text,
	CONSTRAINT "package_versions_package_key_version_pk" PRIMARY KEY("package_key","version")
);
--> statement-breakpoint
CREATE TABLE "packages" (
	"key" text PRIMARY KEY NOT NULL,
	"ecosystem" text NOT NULL,
	"namespace" text,
	"name" text NOT NULL,
	"latest_version" text,
	"latest_checked_at" timestamp with time zone,
	"latest_error" text
);
--> statement-breakpoint
CREATE TABLE "projects" (
	"id" serial PRIMARY KEY NOT NULL,
	"name" text NOT NULL,
	"repository" text,
	"latest_sbom_id" integer,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"updated_at" timestamp with time zone DEFAULT now() NOT NULL,
	CONSTRAINT "projects_name_unique" UNIQUE("name")
);
--> statement-breakpoint
CREATE TABLE "sboms" (
	"id" serial PRIMARY KEY NOT NULL,
	"project_id" integer NOT NULL,
	"version" text,
	"ref" text,
	"commit_sha" text,
	"format" text NOT NULL,
	"spec_version" text,
	"component_count" integer NOT NULL,
	"document" jsonb NOT NULL,
	"uploaded_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "version_vulnerabilities" (
	"package_key" text NOT NULL,
	"version" text NOT NULL,
	"vulnerability_id" text NOT NULL,
	"fixed_versions" jsonb DEFAULT '[]'::jsonb NOT NULL,
	CONSTRAINT "version_vulnerabilities_package_key_version_vulnerability_id_pk" PRIMARY KEY("package_key","version","vulnerability_id")
);
--> statement-breakpoint
CREATE TABLE "vulnerabilities" (
	"id" text PRIMARY KEY NOT NULL,
	"aliases" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"summary" text,
	"details" text,
	"severity" "severity" DEFAULT 'UNKNOWN' NOT NULL,
	"score" real,
	"vector" text,
	"published" timestamp with time zone,
	"modified" timestamp with time zone,
	"references" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"fetched_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "components" ADD CONSTRAINT "components_sbom_id_sboms_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sboms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "package_versions" ADD CONSTRAINT "package_versions_package_key_packages_key_fk" FOREIGN KEY ("package_key") REFERENCES "public"."packages"("key") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "projects" ADD CONSTRAINT "projects_latest_sbom_id_sboms_id_fk" FOREIGN KEY ("latest_sbom_id") REFERENCES "public"."sboms"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sboms" ADD CONSTRAINT "sboms_project_id_projects_id_fk" FOREIGN KEY ("project_id") REFERENCES "public"."projects"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "version_vulnerabilities" ADD CONSTRAINT "version_vulnerabilities_vulnerability_id_vulnerabilities_id_fk" FOREIGN KEY ("vulnerability_id") REFERENCES "public"."vulnerabilities"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "version_vulnerabilities" ADD CONSTRAINT "version_vulnerabilities_package_key_version_package_versions_package_key_version_fk" FOREIGN KEY ("package_key","version") REFERENCES "public"."package_versions"("package_key","version") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "components_sbom_idx" ON "components" USING btree ("sbom_id");--> statement-breakpoint
CREATE INDEX "components_package_idx" ON "components" USING btree ("package_key","version");--> statement-breakpoint
CREATE INDEX "package_versions_checked_idx" ON "package_versions" USING btree ("vulns_checked_at");--> statement-breakpoint
CREATE INDEX "sboms_project_idx" ON "sboms" USING btree ("project_id","uploaded_at");
CREATE TABLE "component_edges" (
	"id" serial PRIMARY KEY NOT NULL,
	"sbom_id" integer NOT NULL,
	"parent_id" integer,
	"child_id" integer NOT NULL
);
--> statement-breakpoint
ALTER TABLE "component_edges" ADD CONSTRAINT "component_edges_sbom_id_sboms_id_fk" FOREIGN KEY ("sbom_id") REFERENCES "public"."sboms"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "component_edges" ADD CONSTRAINT "component_edges_parent_id_components_id_fk" FOREIGN KEY ("parent_id") REFERENCES "public"."components"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "component_edges" ADD CONSTRAINT "component_edges_child_id_components_id_fk" FOREIGN KEY ("child_id") REFERENCES "public"."components"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "component_edges_sbom_idx" ON "component_edges" USING btree ("sbom_id");
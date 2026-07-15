package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect"
	"entgo.io/ent/schema/edge"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
)

// FederatedIdentity holds the schema definition for the FederatedIdentity entity.
// It stores the binding between a Cloudreve user and an external OAuth2/OIDC identity.
type FederatedIdentity struct {
	ent.Schema
}

func (FederatedIdentity) Fields() []ent.Field {
	return []ent.Field{
		field.Int("user_id"),
		field.String("provider"),
		field.String("subject"),
		field.String("union_id").
			Optional(),
		field.Time("last_used_at").
			Optional().
			Nillable().
			SchemaType(map[string]string{
				dialect.MySQL: "datetime",
			}),
	}
}

func (FederatedIdentity) Edges() []ent.Edge {
	return []ent.Edge{
		edge.From("user", User.Type).
			Field("user_id").
			Ref("federated_identities").
			Unique().
			Required(),
	}
}

func (FederatedIdentity) Mixin() []ent.Mixin {
	return []ent.Mixin{
		CommonMixin{},
	}
}

func (FederatedIdentity) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("provider", "subject").
			Unique(),
		index.Fields("user_id"),
	}
}

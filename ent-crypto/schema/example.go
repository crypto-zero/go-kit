package schema

import (
	"time"

	"entgo.io/ent"
	"entgo.io/ent/schema/field"
)

// Example holds the schema definition for the Example entity.
type Example struct {
	ent.Schema

	Username  string
	Email     string
	Password  string
	CreatedAt time.Time
	UpdatedAt time.Time
}

// Fields of the Example.
func (Example) Fields() []ent.Field {
	return []ent.Field{
		field.String("username").NotEmpty(),
		field.String("email").NotEmpty(),
		field.String("password").NotEmpty(),
		field.Time("created_at").Default(time.Now),
		field.Time("updated_at").Default(time.Now),
	}
}

// Edges of the Example.
func (Example) Edges() []ent.Edge {
	return nil
}

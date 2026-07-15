package inventory

import (
	"context"
	"fmt"
	"time"

	"github.com/cloudreve/Cloudreve/v4/ent"
	"github.com/cloudreve/Cloudreve/v4/ent/federatedidentity"
)

type (
	FederatedIdentityClient interface {
		TxOperator
		// GetByProviderSubject returns the federated identity with the given provider and subject.
		// Returns ent.NotFoundError if no binding exists.
		GetByProviderSubject(ctx context.Context, provider, subject string) (*ent.FederatedIdentity, error)
		// Create creates a new federated identity binding.
		Create(ctx context.Context, userID int, provider, subject, unionID string) (*ent.FederatedIdentity, error)
		// MarkUsed updates the last_used_at timestamp.
		MarkUsed(ctx context.Context, id int) error
	}

	federatedIdentityClient struct {
		client *ent.Client
	}
)

func NewFederatedIdentityClient(client *ent.Client) FederatedIdentityClient {
	return &federatedIdentityClient{client: client}
}

func (c *federatedIdentityClient) SetClient(newClient *ent.Client) TxOperator {
	return &federatedIdentityClient{client: newClient}
}

func (c *federatedIdentityClient) GetClient() *ent.Client {
	return c.client
}

func (c *federatedIdentityClient) GetByProviderSubject(ctx context.Context, provider, subject string) (*ent.FederatedIdentity, error) {
	return c.client.FederatedIdentity.Query().
		Where(
			federatedidentity.ProviderEQ(provider),
			federatedidentity.SubjectEQ(subject),
		).
		WithUser().
		First(ctx)
}

func (c *federatedIdentityClient) Create(ctx context.Context, userID int, provider, subject, unionID string) (*ent.FederatedIdentity, error) {
	fi, err := c.client.FederatedIdentity.Create().
		SetUserID(userID).
		SetProvider(provider).
		SetSubject(subject).
		SetUnionID(unionID).
		SetLastUsedAt(time.Now()).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create federated identity: %w", err)
	}
	return fi, nil
}

func (c *federatedIdentityClient) MarkUsed(ctx context.Context, id int) error {
	_, err := c.client.FederatedIdentity.UpdateOneID(id).
		SetLastUsedAt(time.Now()).
		Save(ctx)
	return err
}

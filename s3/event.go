package s3

import (
	"encoding/json"
	"net/url"
	"time"
)

// EventName that wraps the event name
type EventName string

const (
	EventS3ReducedRedundancyLostObject                  EventName = "s3:ReducedRedundancyLostObject"
	EventS3ObjectCreated                                EventName = "s3:ObjectCreated:*"
	EventS3ObjectCreatedPut                             EventName = "s3:ObjectCreated:Put"
	EventS3ObjectCreatedPost                            EventName = "s3:ObjectCreated:Post"
	EventS3ObjectCreatedCopy                            EventName = "s3:ObjectCreated:Copy"
	EventS3ObjectCreatedCompleteMultipartUpload         EventName = "s3:ObjectCreated:CompleteMultipartUpload"
	EventS3ObjectRemoved                                EventName = "s3:ObjectRemoved:*"
	EventS3ObjectRemovedDelete                          EventName = "s3:ObjectRemoved:Delete"
	EventS3ObjectRemovedDeleteMarkerCreated             EventName = "s3:ObjectRemoved:DeleteMarkerCreated"
	EventS3ObjectRestore                                EventName = "s3:ObjectRestore:*"
	EventS3ObjectRestorePost                            EventName = "s3:ObjectRestore:Post"
	EventS3ObjectRestoreCompleted                       EventName = "s3:ObjectRestore:Completed"
	EventS3Replication                                  EventName = "s3:Replication:*"
	EventS3ReplicationOperationFailedReplication        EventName = "s3:Replication:OperationFailedReplication"
	EventS3ReplicationOperationNotTracked               EventName = "s3:Replication:OperationNotTracked"
	EventS3ReplicationOperationMissedThreshold          EventName = "s3:Replication:OperationMissedThreshold"
	EventS3ReplicationOperationReplicatedAfterThreshold EventName = "s3:Replication:OperationReplicatedAfterThreshold"
	EventS3ObjectRestoreDelete                          EventName = "s3:ObjectRestore:Delete"
	EventS3LifecycleTransition                          EventName = "s3:LifecycleTransition"
	EventS3IntelligentTiering                           EventName = "s3:IntelligentTiering"
	EventS3ObjectAclPut                                 EventName = "s3:ObjectAcl:Put"
	EventS3LifecycleExpiration                          EventName = "s3:LifecycleExpiration:*"
	EventS3LifecycleExpirationDelete                    EventName = "s3:LifecycleExpiration:Delete"
	EventS3LifecycleExpirationDeleteMarkerCreated       EventName = "s3:LifecycleExpiration:DeleteMarkerCreated"
	EventS3ObjectTagging                                EventName = "s3:ObjectTagging:*"
	EventS3ObjectTaggingPut                             EventName = "s3:ObjectTagging:Put"
	EventS3ObjectTaggingDelete                          EventName = "s3:ObjectTagging:Delete"
)

// Event that wraps an array of EventRecord
type Event struct {
	EventName EventName     `json:"EventName"`
	Key       string        `json:"Key"`
	Records   []EventRecord `json:"Records"`
}

// EventRecord which wrap record data
type EventRecord struct {
	EventVersion      string            `json:"eventVersion"`
	EventSource       string            `json:"eventSource"`
	AWSRegion         string            `json:"awsRegion"`
	EventTime         time.Time         `json:"eventTime"`
	EventName         EventName         `json:"eventName"`
	PrincipalID       UserIdentity      `json:"userIdentity"`
	RequestParameters RequestParameters `json:"requestParameters"`
	ResponseElements  map[string]string `json:"responseElements"`
	S3                Entity            `json:"s3"`
	Source            Source            `json:"source"`
}

// UserIdentity that wraps the principal ID
type UserIdentity struct {
	PrincipalID string `json:"principalId"`
}

// RequestParameters that wraps the principal ID, region, and source IP address
type RequestParameters struct {
	PrincipalID     string `json:"principalId"`
	Region          string `json:"region"`
	SourceIPAddress string `json:"sourceIPAddress"`
}

// Entity that wraps the bucket and object
type Entity struct {
	SchemaVersion   string `json:"s3SchemaVersion"`
	ConfigurationID string `json:"configurationId"`
	Bucket          Bucket `json:"bucket"`
	Object          Object `json:"object"`
}

// Bucket that wraps the bucket name, owner identity, and ARN
type Bucket struct {
	Name          string       `json:"name"`
	OwnerIdentity UserIdentity `json:"ownerIdentity"`
	ARN           string       `json:"arn"` //nolint: stylecheck
}

// Object that wraps the object key, size, ETag, content type, user metadata,
// version ID, sequencer, and URL-decoded key
type Object struct {
	Key           string            `json:"key"`
	Size          int64             `json:"size,omitempty"`
	ETag          string            `json:"eTag"`
	ContentType   string            `json:"contentType"`
	UserMetadata  map[string]string `json:"userMetadata"`
	VersionID     string            `json:"versionId"`
	Sequencer     string            `json:"sequencer"`
	URLDecodedKey string            `json:"urlDecodedKey"`
}

func (o *Object) UnmarshalJSON(data []byte) error {
	type rawS3Object Object
	if err := json.Unmarshal(data, (*rawS3Object)(o)); err != nil {
		return err
	}
	key, err := url.QueryUnescape(o.Key)
	if err != nil {
		return err
	}
	o.URLDecodedKey = key
	return nil
}

// Source that wraps the source IP address and user agent
type Source struct {
	Host      string `json:"host"`
	Port      string `json:"port"`
	UserAgent string `json:"userAgent"`
}

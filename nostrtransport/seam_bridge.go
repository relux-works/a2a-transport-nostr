package nostrtransport

// Public T0 contract pinned to the landed upstream commit in go.mod.
import seam "github.com/relux-works/a2a-swarm/transport"

type SeamConfig = seam.Config
type SeamTransport = seam.Transport
type Principal = seam.Principal
type PrincipalID = seam.PrincipalID
type ConversationID = seam.ConversationID
type EventID = seam.EventID
type Cursor = seam.Cursor
type Message = seam.Message
type SendRequest = seam.SendRequest
type SendResult = seam.SendResult
type Event = seam.Event
type Batch = seam.Batch
type Gap = seam.Gap
type GapReason = seam.GapReason
type SyncOptions = seam.SyncOptions
type Page = seam.Page
type Member = seam.Member
type MediaRef = seam.MediaRef
type MediaMeta = seam.MediaMeta
type Capabilities = seam.Capabilities
type ConversationCaps = seam.ConversationCaps
type Addressing = seam.Addressing

const (
	maxRawBytes          = seam.MaxRawBytes
	ACK                  = seam.ACK
	UNKNOWN              = seam.UNKNOWN
	REFUSED              = seam.REFUSED
	redactionNone        = seam.NoRedaction
	membershipSenderSide = seam.SenderSide
)

var seamError = seam.NewError
var newRefusal = seam.NewRefusal
var mediaRef = seam.NewMediaRef

// Registration errors stay observable, never panic during application init.
var RegistrationError error

func init() {
	RegistrationError = seam.Register("nostr", func(c seam.Config) (seam.Transport, error) { return Open(c) })
}

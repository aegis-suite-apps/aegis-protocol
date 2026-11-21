package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode/utf8"
)

// ---------------------------------------------------------------------------
// Documentos legales
// ---------------------------------------------------------------------------

type LegalDocumentKind string

const (
	LegalTerms   LegalDocumentKind = "terms"
	LegalPrivacy LegalDocumentKind = "privacy"
)

// LegalDocument describe una versión publicada de un documento legal en Aegis RD.
// URL apunta a la página pública legible; RawURL al Markdown exacto cuyo
// SHA-256 es SHA256.
type LegalDocument struct {
	Kind        LegalDocumentKind `json:"kind"`
	Version     string            `json:"version"`
	SHA256      string            `json:"sha256"`
	Title       string            `json:"title"`
	URL         string            `json:"url"`
	RawURL      string            `json:"raw_url"`
	PublishedAt string            `json:"published_at"`
}

// LegalManifest es la versión vigente de los documentos legales de un producto.
type LegalManifest struct {
	Product ProductID     `json:"product"`
	Terms   LegalDocument `json:"terms"`
	Privacy LegalDocument `json:"privacy"`
}

// ---------------------------------------------------------------------------
// Aceptación de términos
// ---------------------------------------------------------------------------

type TermsAcceptanceMethod string

const (
	// AcceptedInInstaller: la persona que instaló aceptó en el asistente.
	AcceptedInInstaller TermsAcceptanceMethod = "installer"
	// AcceptedInApp: aceptación dentro de la app (versión nueva de términos o
	// instalación silenciosa sin aceptación previa).
	AcceptedInApp TermsAcceptanceMethod = "app"
	// AcceptedByAdministrator: instalación silenciosa con aceptación explícita
	// del administrador (/ACCEPTTERMS).
	AcceptedByAdministrator TermsAcceptanceMethod = "administrator"
)

func (m TermsAcceptanceMethod) Valid() bool {
	switch m {
	case AcceptedInInstaller, AcceptedInApp, AcceptedByAdministrator:
		return true
	}
	return false
}

type TermsAcceptance struct {
	TermsVersion   string                `json:"terms_version"`
	TermsSHA256    string                `json:"terms_sha256"`
	PrivacyVersion string                `json:"privacy_version"`
	PrivacySHA256  string                `json:"privacy_sha256"`
	AcceptedAt     string                `json:"accepted_at"`
	Method         TermsAcceptanceMethod `json:"method"`
	AppVersion     string                `json:"app_version"`
}

// Validate comprueba la forma del registro antes de enviarlo o guardarlo.
func (a TermsAcceptance) Validate() error {
	switch {
	case strings.TrimSpace(a.TermsVersion) == "":
		return errors.New("terms_version requerido")
	case !isSHA256Hex(a.TermsSHA256):
		return errors.New("terms_sha256 inválido")
	case strings.TrimSpace(a.PrivacyVersion) == "":
		return errors.New("privacy_version requerido")
	case !isSHA256Hex(a.PrivacySHA256):
		return errors.New("privacy_sha256 inválido")
	case !a.Method.Valid():
		return fmt.Errorf("method inválido: %q", a.Method)
	}
	if _, err := parseServerTimeUnix(a.AcceptedAt); err != nil {
		return errors.New("accepted_at debe ser RFC3339")
	}
	return nil
}

// Covers indica si esta aceptación cubre exactamente los documentos dados.
func (a TermsAcceptance) Covers(terms, privacy LegalDocument) bool {
	return a.Validate() == nil &&
		a.TermsVersion == terms.Version && strings.EqualFold(a.TermsSHA256, terms.SHA256) &&
		a.PrivacyVersion == privacy.Version && strings.EqualFold(a.PrivacySHA256, privacy.SHA256)
}

func isSHA256Hex(v string) bool {
	if len(v) != 64 {
		return false
	}
	for _, r := range v {
		if !(r >= '0' && r <= '9' || r >= 'a' && r <= 'f' || r >= 'A' && r <= 'F') {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Tickets desde el equipo
// ---------------------------------------------------------------------------

type TicketStatus string

const (
	TicketOpen            TicketStatus = "open"
	TicketPending         TicketStatus = "pending"
	TicketWaitingCustomer TicketStatus = "waiting_customer"
	TicketResolved        TicketStatus = "resolved"
	TicketClosed          TicketStatus = "closed"
)

// Límites compartidos con Aegis RD (mismos valores en ts/src/schema.ts).
const (
	TicketSubjectMax = 160
	TicketBodyMax    = 8000
	TicketNameMax    = 120
	TicketEmailMax   = 254
	TicketPhoneMax   = 40
)

type CreateTicketRequest struct {
	Subject      string         `json:"subject"`
	Body         string         `json:"body"`
	ContactName  string         `json:"contact_name"`
	ContactEmail string         `json:"contact_email"`
	ContactPhone string         `json:"contact_phone,omitempty"`
	Diagnostics  map[string]any `json:"diagnostics,omitempty"`
}

func (r CreateTicketRequest) Validate() error {
	subject := strings.TrimSpace(r.Subject)
	body := strings.TrimSpace(r.Body)
	name := strings.TrimSpace(r.ContactName)
	email := strings.TrimSpace(r.ContactEmail)
	switch {
	case subject == "" || utf8.RuneCountInString(subject) > TicketSubjectMax:
		return fmt.Errorf("el asunto es obligatorio (máximo %d caracteres)", TicketSubjectMax)
	case body == "" || utf8.RuneCountInString(body) > TicketBodyMax:
		return fmt.Errorf("la descripción es obligatoria (máximo %d caracteres)", TicketBodyMax)
	case name == "" || utf8.RuneCountInString(name) > TicketNameMax:
		return errors.New("tu nombre es obligatorio")
	case !looksLikeEmail(email) || len(email) > TicketEmailMax:
		return errors.New("el correo de contacto no es válido")
	case utf8.RuneCountInString(strings.TrimSpace(r.ContactPhone)) > TicketPhoneMax:
		return errors.New("el teléfono es demasiado largo")
	}
	return nil
}

func looksLikeEmail(v string) bool {
	at := strings.LastIndex(v, "@")
	if at < 1 || at == len(v)-1 || strings.ContainsAny(v, " \t\r\n<>") {
		return false
	}
	return strings.Contains(v[at+1:], ".")
}

type Ticket struct {
	ID            string       `json:"id"`
	Number        int          `json:"number"`
	Subject       string       `json:"subject"`
	Status        TicketStatus `json:"status"`
	CreatedAt     string       `json:"created_at"`
	UpdatedAt     string       `json:"updated_at"`
	LastMessageAt string       `json:"last_message_at"`
	// AwaitingYou es true cuando la última respuesta visible es del equipo de soporte.
	AwaitingYou bool `json:"awaiting_you"`
}

type TicketAuthor string

const (
	TicketAuthorDevice  TicketAuthor = "device"
	TicketAuthorSupport TicketAuthor = "support"
)

type TicketMessage struct {
	ID         string       `json:"id"`
	Author     TicketAuthor `json:"author"`
	AuthorName string       `json:"author_name"`
	Body       string       `json:"body"`
	CreatedAt  string       `json:"created_at"`
}

type TicketDetail struct {
	Ticket   Ticket          `json:"ticket"`
	Messages []TicketMessage `json:"messages"`
}

type ticketList struct {
	Tickets []Ticket `json:"tickets"`
}

type ticketReply struct {
	Body string `json:"body"`
}

type ticketCreated struct {
	Ticket Ticket `json:"ticket"`
}

type ticketMessageCreated struct {
	Message TicketMessage `json:"message"`
}

// ---------------------------------------------------------------------------
// Llamadas HTTP
// ---------------------------------------------------------------------------

// FetchLegalManifest lee la versión vigente de términos y privacidad (público).
func (c *Client) FetchLegalManifest(ctx context.Context, baseURL string, product ProductID) (LegalManifest, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return LegalManifest{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/api/v2/legal/"+url.PathEscape(string(product)), nil)
	if err != nil {
		return LegalManifest{}, err
	}
	req.Header.Set("accept", "application/json")
	var out LegalManifest
	if err := c.do(req, http.StatusOK, &out); err != nil {
		return LegalManifest{}, err
	}
	if out.Product != product || !isSHA256Hex(out.Terms.SHA256) || !isSHA256Hex(out.Privacy.SHA256) {
		return LegalManifest{}, errors.New("Aegis RD devolvió un manifiesto legal incompleto")
	}
	return out, nil
}

func (c *Client) SendTermsAcceptance(ctx context.Context, baseURL, token string, acceptance TermsAcceptance) error {
	if err := acceptance.Validate(); err != nil {
		return err
	}
	req, err := c.jsonRequest(ctx, http.MethodPost, baseURL, "/api/v2/agent/terms-acceptance", token, acceptance)
	if err != nil {
		return err
	}
	return c.do(req, http.StatusNoContent, nil)
}

func (c *Client) CreateTicket(ctx context.Context, baseURL, token string, in CreateTicketRequest) (Ticket, error) {
	in.Subject = strings.TrimSpace(in.Subject)
	in.Body = strings.TrimSpace(in.Body)
	in.ContactName = strings.TrimSpace(in.ContactName)
	in.ContactEmail = strings.TrimSpace(in.ContactEmail)
	in.ContactPhone = strings.TrimSpace(in.ContactPhone)
	if err := in.Validate(); err != nil {
		return Ticket{}, err
	}
	req, err := c.jsonRequest(ctx, http.MethodPost, baseURL, "/api/v2/agent/tickets", token, in)
	if err != nil {
		return Ticket{}, err
	}
	var out ticketCreated
	if err := c.do(req, http.StatusCreated, &out); err != nil {
		return Ticket{}, err
	}
	return out.Ticket, nil
}

func (c *Client) ListTickets(ctx context.Context, baseURL, token string) ([]Ticket, error) {
	req, err := c.jsonRequest(ctx, http.MethodGet, baseURL, "/api/v2/agent/tickets", token, nil)
	if err != nil {
		return nil, err
	}
	var out ticketList
	if err := c.do(req, http.StatusOK, &out); err != nil {
		return nil, err
	}
	if out.Tickets == nil {
		out.Tickets = []Ticket{}
	}
	return out.Tickets, nil
}

func (c *Client) GetTicket(ctx context.Context, baseURL, token, ticketID string) (TicketDetail, error) {
	if strings.TrimSpace(ticketID) == "" {
		return TicketDetail{}, errors.New("ticket id requerido")
	}
	req, err := c.jsonRequest(ctx, http.MethodGet, baseURL, "/api/v2/agent/tickets/"+url.PathEscape(ticketID), token, nil)
	if err != nil {
		return TicketDetail{}, err
	}
	var out TicketDetail
	if err := c.do(req, http.StatusOK, &out); err != nil {
		return TicketDetail{}, err
	}
	if out.Messages == nil {
		out.Messages = []TicketMessage{}
	}
	return out, nil
}

func (c *Client) ReplyTicket(ctx context.Context, baseURL, token, ticketID, body string) (TicketMessage, error) {
	body = strings.TrimSpace(body)
	if body == "" || utf8.RuneCountInString(body) > TicketBodyMax {
		return TicketMessage{}, fmt.Errorf("el mensaje es obligatorio (máximo %d caracteres)", TicketBodyMax)
	}
	if strings.TrimSpace(ticketID) == "" {
		return TicketMessage{}, errors.New("ticket id requerido")
	}
	req, err := c.jsonRequest(ctx, http.MethodPost, baseURL, "/api/v2/agent/tickets/"+url.PathEscape(ticketID)+"/messages", token, ticketReply{Body: body})
	if err != nil {
		return TicketMessage{}, err
	}
	var out ticketMessageCreated
	if err := c.do(req, http.StatusCreated, &out); err != nil {
		return TicketMessage{}, err
	}
	return out.Message, nil
}

func (c *Client) jsonRequest(ctx context.Context, method, baseURL, path, token string, payload any) (*http.Request, error) {
	base, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	if strings.TrimSpace(token) == "" {
		return nil, errors.New("token de instalación requerido")
	}
	var body *bytes.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return nil, err
		}
		body = bytes.NewReader(raw)
	}
	var req *http.Request
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, base+path, body)
	} else {
		req, err = http.NewRequestWithContext(ctx, method, base+path, nil)
	}
	if err != nil {
		return nil, err
	}
	if payload != nil {
		req.Header.Set("content-type", "application/json")
	}
	req.Header.Set("accept", "application/json")
	req.Header.Set("authorization", "Bearer "+token)
	return req, nil
}

// ---------------------------------------------------------------------------
// Métodos del agente (usan la credencial enrolada)
// ---------------------------------------------------------------------------

func (a *Agent) credentials() (string, string, error) {
	enrolled, err := a.store.LoadEnrollment()
	if err != nil {
		return "", "", err
	}
	return enrolled.Config.WorkerBaseURL, enrolled.InstallationToken, nil
}

func (a *Agent) LegalManifest(ctx context.Context) (LegalManifest, error) {
	base, _, err := a.credentials()
	if err != nil {
		return LegalManifest{}, err
	}
	return a.client.FetchLegalManifest(ctx, base, a.product)
}

func (a *Agent) ReportTermsAcceptance(ctx context.Context, acceptance TermsAcceptance) error {
	base, token, err := a.credentials()
	if err != nil {
		return err
	}
	return a.client.SendTermsAcceptance(ctx, base, token, acceptance)
}

func (a *Agent) CreateTicket(ctx context.Context, in CreateTicketRequest) (Ticket, error) {
	base, token, err := a.credentials()
	if err != nil {
		return Ticket{}, err
	}
	return a.client.CreateTicket(ctx, base, token, in)
}

func (a *Agent) ListTickets(ctx context.Context) ([]Ticket, error) {
	base, token, err := a.credentials()
	if err != nil {
		return nil, err
	}
	return a.client.ListTickets(ctx, base, token)
}

func (a *Agent) GetTicket(ctx context.Context, id string) (TicketDetail, error) {
	base, token, err := a.credentials()
	if err != nil {
		return TicketDetail{}, err
	}
	return a.client.GetTicket(ctx, base, token, id)
}

func (a *Agent) ReplyTicket(ctx context.Context, id, body string) (TicketMessage, error) {
	base, token, err := a.credentials()
	if err != nil {
		return TicketMessage{}, err
	}
	return a.client.ReplyTicket(ctx, base, token, id, body)
}

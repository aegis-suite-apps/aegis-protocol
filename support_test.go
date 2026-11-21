package protocol_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	protocol "github.com/aegis-suite-apps/aegis-protocol"
)

const sha = "0e2f6559885896acf15fba2af28b4bedb3813012eb8e7715eb77c90ef49c725b"

func validAcceptance() protocol.TermsAcceptance {
	return protocol.TermsAcceptance{
		TermsVersion:   "0.2.0",
		TermsSHA256:    sha,
		PrivacyVersion: "0.2.0",
		PrivacySHA256:  sha,
		AcceptedAt:     "2026-11-20T10:00:00Z",
		Method:         protocol.AcceptedInInstaller,
		AppVersion:     "1.0.0",
	}
}

func TestTermsAcceptanceValidateAndCovers(t *testing.T) {
	a := validAcceptance()
	if err := a.Validate(); err != nil {
		t.Fatalf("valid acceptance rejected: %v", err)
	}
	doc := protocol.LegalDocument{Version: "0.2.0", SHA256: strings.ToUpper(sha)}
	if !a.Covers(doc, doc) {
		t.Fatal("acceptance should cover same version/hash (case-insensitive)")
	}
	newer := protocol.LegalDocument{Version: "0.3.0", SHA256: sha}
	if a.Covers(newer, doc) {
		t.Fatal("acceptance must not cover a newer terms version")
	}
	bad := a
	bad.Method = "ui"
	if bad.Validate() == nil {
		t.Fatal("unknown method must be rejected")
	}
	bad = a
	bad.AcceptedAt = "ayer"
	if bad.Validate() == nil {
		t.Fatal("non RFC3339 date must be rejected")
	}
}

func TestCreateTicketRequestValidate(t *testing.T) {
	ok := protocol.CreateTicketRequest{Subject: "No abre", Body: "Al abrir da error", ContactName: "Ana", ContactEmail: "ana@example.com"}
	if err := ok.Validate(); err != nil {
		t.Fatalf("valid ticket rejected: %v", err)
	}
	for name, mutate := range map[string]func(*protocol.CreateTicketRequest){
		"empty subject": func(r *protocol.CreateTicketRequest) { r.Subject = " " },
		"long subject":  func(r *protocol.CreateTicketRequest) { r.Subject = strings.Repeat("a", protocol.TicketSubjectMax+1) },
		"empty body":    func(r *protocol.CreateTicketRequest) { r.Body = "" },
		"no name":       func(r *protocol.CreateTicketRequest) { r.ContactName = "" },
		"bad email":     func(r *protocol.CreateTicketRequest) { r.ContactEmail = "ana@" },
	} {
		r := ok
		mutate(&r)
		if r.Validate() == nil {
			t.Errorf("%s: expected validation error", name)
		}
	}
}

func TestSupportClientRoundTrip(t *testing.T) {
	var gotAcceptance map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v2/legal/aegis-launch" && r.Header.Get("authorization") != "Bearer tok-123" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.Path {
		case "GET /api/v2/legal/aegis-launch":
			_ = json.NewEncoder(w).Encode(protocol.LegalManifest{
				Product: protocol.ProductLaunch,
				Terms:   protocol.LegalDocument{Kind: protocol.LegalTerms, Version: "0.2.0", SHA256: sha},
				Privacy: protocol.LegalDocument{Kind: protocol.LegalPrivacy, Version: "0.2.0", SHA256: sha},
			})
		case "POST /api/v2/agent/terms-acceptance":
			_ = json.NewDecoder(r.Body).Decode(&gotAcceptance)
			w.WriteHeader(http.StatusNoContent)
		case "POST /api/v2/agent/tickets":
			var in protocol.CreateTicketRequest
			_ = json.NewDecoder(r.Body).Decode(&in)
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"ticket": protocol.Ticket{ID: "tkt_1", Number: 42, Subject: in.Subject, Status: protocol.TicketOpen}})
		case "GET /api/v2/agent/tickets":
			_ = json.NewEncoder(w).Encode(map[string]any{"tickets": []protocol.Ticket{{ID: "tkt_1", Number: 42}}})
		case "GET /api/v2/agent/tickets/tkt_1":
			_ = json.NewEncoder(w).Encode(protocol.TicketDetail{Ticket: protocol.Ticket{ID: "tkt_1"}, Messages: []protocol.TicketMessage{{ID: "m1", Author: protocol.TicketAuthorSupport, Body: "Hola"}}})
		case "POST /api/v2/agent/tickets/tkt_1/messages":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]any{"message": protocol.TicketMessage{ID: "m2", Author: protocol.TicketAuthorDevice, Body: "Gracias"}})
		default:
			w.WriteHeader(http.StatusNotFound)
			_, _ = w.Write([]byte(`{"error":{"code":"not_found","message":"no"}}`))
		}
	}))
	defer srv.Close()

	ctx := context.Background()
	c := &protocol.Client{HTTP: srv.Client()}

	manifest, err := c.FetchLegalManifest(ctx, srv.URL, protocol.ProductLaunch)
	if err != nil || manifest.Terms.Version != "0.2.0" {
		t.Fatalf("manifest: %+v %v", manifest, err)
	}
	if err := c.SendTermsAcceptance(ctx, srv.URL, "tok-123", validAcceptance()); err != nil {
		t.Fatalf("terms acceptance: %v", err)
	}
	if gotAcceptance["terms_version"] != "0.2.0" || gotAcceptance["method"] != "installer" || gotAcceptance["terms_sha256"] != sha {
		t.Fatalf("acceptance must be sent in snake_case, got %v", gotAcceptance)
	}
	ticket, err := c.CreateTicket(ctx, srv.URL, "tok-123", protocol.CreateTicketRequest{Subject: " No abre ", Body: "Error", ContactName: "Ana", ContactEmail: "ana@example.com"})
	if err != nil || ticket.Number != 42 || ticket.Subject != "No abre" {
		t.Fatalf("create ticket: %+v %v", ticket, err)
	}
	list, err := c.ListTickets(ctx, srv.URL, "tok-123")
	if err != nil || len(list) != 1 {
		t.Fatalf("list tickets: %+v %v", list, err)
	}
	detail, err := c.GetTicket(ctx, srv.URL, "tok-123", "tkt_1")
	if err != nil || len(detail.Messages) != 1 || detail.Messages[0].Author != protocol.TicketAuthorSupport {
		t.Fatalf("get ticket: %+v %v", detail, err)
	}
	msg, err := c.ReplyTicket(ctx, srv.URL, "tok-123", "tkt_1", "Gracias")
	if err != nil || msg.ID != "m2" {
		t.Fatalf("reply: %+v %v", msg, err)
	}
	if _, err := c.GetTicket(ctx, srv.URL, "tok-123", "otro"); err == nil {
		t.Fatal("expected HTTP error for unknown ticket")
	} else if httpErr, ok := err.(*protocol.HTTPError); !ok || httpErr.Status != 404 {
		t.Fatalf("expected HTTPError 404, got %v", err)
	}
	if _, err := c.ListTickets(ctx, srv.URL, ""); err == nil {
		t.Fatal("empty token must be rejected locally")
	}
}

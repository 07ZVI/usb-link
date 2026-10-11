package updater

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

type updateObservation struct {
	Version string `json:"version"`
	Update  struct {
		ID, Status, Detail string
		Deployment         string `json:"deployment_state"`
		USB                string `json:"usb_state"`
		PersistenceRetry   string `json:"persistence_retry"`
		RetryID            string `json:"retry_job_id"`
	} `json:"update"`
}

// Installation, process survival and actual USB readiness are separate facts.
// Legacy servers omit the latter; their client success confirms version only.
func classifyUpdateOutcome(s updateObservation, wanted string) (bool, error) {
	switch s.Update.Status {
	case "complete":
		if s.Version != wanted {
			return false, fmt.Errorf("version confirmation mismatch")
		}
		if s.Update.USB != "" && (s.Update.USB != "verified" || s.Update.Deployment != "installed") {
			return false, fmt.Errorf("version installed but USB readiness unverified")
		}
		return true, nil
	case "deployed_recovery_required", "deployed_not_running":
		return false, fmt.Errorf("deployment reported %s; ordinary USB readiness is not confirmed: %s", s.Update.Status, s.Update.Detail)
	case "declined", "failed", "cancelled", "interrupted", "rollback", "rollback_running", "rollback_failed", "manual_recovery_required", "persistence_recovery_required":
		return false, fmt.Errorf("update ended: %s: %s", s.Update.Status, s.Update.Detail)
	}
	return false, nil
}

func ownedCancellationPayload(b []byte) ([]byte, string, error) {
	var s updateObservation
	if json.Unmarshal(b, &s) != nil {
		return nil, "", fmt.Errorf("invalid current update status")
	}
	id := s.Update.ID
	retry := s.Update.Status == "persistence_recovery_required" && s.Update.PersistenceRetry == "true" && s.Update.RetryID == id
	raw, err := hex.DecodeString(id)
	if err != nil || len(raw) != 16 || hex.EncodeToString(raw) != id || s.Update.Status != "staged" && !retry {
		return nil, "", fmt.Errorf("only the current idle staged update can be cancelled")
	}
	payload, err := json.Marshal(map[string]string{"id": id})
	return payload, id, err
}

func verifyCancellationAck(b []byte, id string) error {
	var ack struct{ ID, Status string }
	if json.Unmarshal(b, &ack) != nil || ack.ID != id || ack.Status != "cancelled" && ack.Status != "persistence_recovered" {
		return fmt.Errorf("owned update cancellation was not confirmed")
	}
	return nil
}

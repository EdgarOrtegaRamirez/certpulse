// Package score provides certificate security scoring.
package score

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/EdgarOrtegaRamirez/certpulse/internal/inspect"
)

// SecurityScore holds the scoring results.
type SecurityScore struct {
	Score          uint32        `json:"score"`
	Grade          string        `json:"grade"`
	Details        []ScoreDetail `json:"details"`
	Recommendations []string     `json:"recommendations,omitempty"`
}

// ScoreDetail holds a single scoring category.
type ScoreDetail struct {
	Category string `json:"category"`
	Score    uint32 `json:"score"`
	MaxScore uint32 `json:"max_score"`
	Status   string `json:"status"`
	Message  string `json:"message"`
}

// ScoreCertificate evaluates a certificate's security, returning a 0-100 score.
func ScoreCertificate(info inspect.Info) SecurityScore {
	var details []ScoreDetail
	var recommendations []string

	// 1. Key strength (max 25 points)
	keyScore, keyStatus, keyMsg := scoreKeyStrength(info)
	details = append(details, ScoreDetail{Category: "Key Strength", Score: keyScore, MaxScore: 25, Status: keyStatus, Message: keyMsg})
	if keyStatus == "critical" {
		recommendations = append(recommendations, fmt.Sprintf("Weak key size: %d bits. Use at least 2048-bit RSA or 256-bit ECC.", info.KeySize))
	} else if keyStatus == "warning" {
		recommendations = append(recommendations, fmt.Sprintf("Key size %d bits is marginal. Prefer 2048+ RSA or 256+ EC.", info.KeySize))
	}

	// 2. Signature algorithm (max 20 points)
	sigScore, sigStatus, sigMsg := scoreSignature(info)
	details = append(details, ScoreDetail{Category: "Signature Algorithm", Score: sigScore, MaxScore: 20, Status: sigStatus, Message: sigMsg})
	if sigStatus == "critical" {
		recommendations = append(recommendations, fmt.Sprintf("Weak signature algorithm: %s. Use SHA-256 or stronger.", info.SignatureAlgorithm))
	} else if sigStatus == "warning" {
		recommendations = append(recommendations, fmt.Sprintf("Signature algorithm %s is deprecated. Upgrade to SHA-256+.", info.SignatureAlgorithm))
	}

	// 3. Expiry proximity (max 20 points)
	expScore, expStatus, expMsg := scoreExpiry(info)
	details = append(details, ScoreDetail{Category: "Expiry Proximity", Score: expScore, MaxScore: 20, Status: expStatus, Message: expMsg})
	if expStatus == "critical" {
		recommendations = append(recommendations, "Certificate is expired. Renew immediately.")
	} else if expStatus == "warning" {
		recommendations = append(recommendations, fmt.Sprintf("Certificate expires in %d days. Renew soon.", info.DaysRemaining))
	}

	// 4. SAN presence (max 15 points)
	sanScore, sanStatus, sanMsg := scoreSAN(info)
	details = append(details, ScoreDetail{Category: "Subject Alternative Names", Score: sanScore, MaxScore: 15, Status: sanStatus, Message: sanMsg})
	if sanStatus == "critical" {
		recommendations = append(recommendations, "No Subject Alternative Names (SANs) found. Modern browsers require SANs.")
	}

	// 5. Chain & CA properties (max 20 points)
	chainScore, _, chainMsg := scoreChain(info)
	details = append(details, ScoreDetail{Category: "Chain & CA Properties", Score: chainScore, MaxScore: 20, Status: "pass", Message: chainMsg})

	total := keyScore + sigScore + expScore + sanScore + chainScore
	if total > 100 {
		total = 100
	}

	grade := ""
	switch {
	case total >= 90:
		grade = "A"
	case total >= 80:
		grade = "B"
	case total >= 70:
		grade = "C"
	case total >= 60:
		grade = "D"
	default:
		grade = "F"
	}

	return SecurityScore{Score: total, Grade: grade, Details: details, Recommendations: recommendations}
}

func scoreKeyStrength(info inspect.Info) (uint32, string, string) {
	if info.KeySize == 0 {
		return 0, "critical", "Unknown key type"
	}
	isEC := strings.Contains(info.PublicKeyAlgorithm, "EC") || strings.Contains(info.PublicKeyAlgorithm, "ecdsa")
	if isEC {
		if info.KeySize >= 521 {
			return 25, "pass", fmt.Sprintf("EC %d bits (very strong)", info.KeySize)
		} else if info.KeySize >= 384 {
			return 25, "pass", fmt.Sprintf("EC %d bits (strong)", info.KeySize)
		} else if info.KeySize >= 256 {
			return 25, "pass", fmt.Sprintf("EC %d bits (adequate, ≈RSA 3072)", info.KeySize)
		}
		return 10, "warning", fmt.Sprintf("EC %d bits (weak)", info.KeySize)
	}
	if info.KeySize >= 4096 {
		return 25, "pass", fmt.Sprintf("%d bits (very strong)", info.KeySize)
	} else if info.KeySize >= 2048 {
		return 20, "pass", fmt.Sprintf("%d bits (adequate)", info.KeySize)
	} else if info.KeySize >= 1024 {
		return 10, "warning", fmt.Sprintf("%d bits (weak, < 2048)", info.KeySize)
	}
	return 0, "critical", fmt.Sprintf("%d bits (very weak)", info.KeySize)
}

func scoreSignature(info inspect.Info) (uint32, string, string) {
	s := strings.ToUpper(info.SignatureAlgorithm)
	if strings.Contains(s, "SHA512") || strings.Contains(s, "SHA384") {
		return 20, "pass", info.SignatureAlgorithm + " (strong)"
	} else if strings.Contains(s, "SHA256") {
		return 18, "pass", info.SignatureAlgorithm + " (adequate)"
	} else if strings.Contains(s, "SHA1") {
		return 5, "warning", info.SignatureAlgorithm + " (deprecated)"
	} else if strings.Contains(s, "MD5") || strings.Contains(s, "MD4") {
		return 0, "critical", info.SignatureAlgorithm + " (broken)"
	}
	return 10, "warning", info.SignatureAlgorithm + " (unknown strength)"
}

func scoreExpiry(info inspect.Info) (uint32, string, string) {
	if info.Expired {
		return 0, "critical", fmt.Sprintf("Expired since %s", info.NotAfter)
	}
	if info.DaysRemaining > 365 {
		return 20, "pass", fmt.Sprintf("%d days remaining (well within validity)", info.DaysRemaining)
	} else if info.DaysRemaining > 90 {
		return 15, "pass", fmt.Sprintf("%d days remaining", info.DaysRemaining)
	} else if info.DaysRemaining > 30 {
		return 10, "warning", fmt.Sprintf("%d days remaining (renew soon)", info.DaysRemaining)
	} else if info.DaysRemaining > 7 {
		return 5, "warning", fmt.Sprintf("%d days remaining (renew urgently)", info.DaysRemaining)
	}
	return 0, "critical", fmt.Sprintf("%d days remaining (expiring)", info.DaysRemaining)
}

func scoreSAN(info inspect.Info) (uint32, string, string) {
	if info.IsCA {
		return 15, "pass", "CA certificate (SANs not required)"
	}
	if len(info.SANs) == 0 {
		return 0, "critical", "No SANs (required for modern TLS)"
	}
	if len(info.SANs) >= 5 {
		return 15, "pass", fmt.Sprintf("%d SANs present", len(info.SANs))
	}
	return 12, "pass", fmt.Sprintf("%d SANs present", len(info.SANs))
}

func scoreChain(info inspect.Info) (uint32, string, string) {
	score := uint32(10)
	msg := ""
	if info.IsCA {
		score += 10
		msg = "CA certificate"
	} else if info.Subject == info.Issuer {
		score += 5
		msg = "Self-signed"
	} else {
		score += 10
		msg = "CA-issued certificate"
	}
	if score > 20 {
		score = 20
	}
	return score, "pass", msg
}

// PrintScore prints the scoring result in the given format.
func PrintScore(score SecurityScore, format string, w io.Writer) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(score)
	case "yaml":
		return printYAML(score, w)
	default:
		return printText(score, w)
	}
}

func printYAML(score SecurityScore, w io.Writer) error {
	fmt.Fprintf(w, "score: %d\n", score.Score)
	fmt.Fprintf(w, "grade: %s\n", score.Grade)
	fmt.Fprintf(w, "details:\n")
	for _, d := range score.Details {
		fmt.Fprintf(w, "  - category: %s\n", d.Category)
		fmt.Fprintf(w, "    score: %d\n", d.Score)
		fmt.Fprintf(w, "    max_score: %d\n", d.MaxScore)
		fmt.Fprintf(w, "    status: %s\n", d.Status)
		fmt.Fprintf(w, "    message: %s\n", d.Message)
	}
	fmt.Fprintf(w, "recommendations:\n")
	for _, r := range score.Recommendations {
		fmt.Fprintf(w, "  - %s\n", r)
	}
	return nil
}

func printText(score SecurityScore, w io.Writer) error {
	_ = gradeColor(score.Grade)
	fmt.Fprintf(w, "\nSecurity Score: %d/100  Grade: %s\n", score.Score, score.Grade)
	fmt.Fprintf(w, "═══════════════════════════════════════\n")

	fmt.Fprintf(w, "\nScore Breakdown:\n")
	for _, d := range score.Details {
		icon := "✓"
		if d.Status == "warning" {
			icon = "⚠"
		} else if d.Status == "critical" {
			icon = "✗"
		}
		barLen := int(d.Score) / 2
		if barLen < 1 {
			barLen = 1
		}
		maxBar := int(d.MaxScore) / 2
		if barLen > maxBar {
			barLen = maxBar
		}
		bar := strings.Repeat("▓", barLen)
		fmt.Fprintf(w, "  %s %-30s %s  %d/%d  %s\n", icon, d.Category+":", bar, d.Score, d.MaxScore, d.Message)
	}

	if len(score.Recommendations) > 0 {
		fmt.Fprintf(w, "\nRecommendations:\n")
		for _, rec := range score.Recommendations {
			fmt.Fprintf(w, "  • %s\n", rec)
		}
	}
	fmt.Fprintf(w, "\n")
	return nil
}

func gradeColor(grade string) string {
	switch grade {
	case "A", "B":
		return grade
	case "C", "D":
		return grade
	default:
		return grade
	}
}

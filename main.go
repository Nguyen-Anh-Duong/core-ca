package main

import (
	"context"
	"core-ca/ca/model"
	ca_repository "core-ca/ca/repository"
	ca_service "core-ca/ca/service"
	"core-ca/config"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"core-ca/keymanagement/repository"
	"core-ca/keymanagement/service"
	"crypto/x509"
	"database/sql"
	"encoding/pem"

	_ "core-ca/docs"

	"github.com/gin-gonic/gin"
	_ "github.com/jackc/pgx/v5/stdlib"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"

	"net/http"
)

// @title Core CA API
// @version 1.0
// @description Certificate Authority API for key management and certificate operations
// @termsOfService http://swagger.io/terms/

// @contact.name API Support
// @contact.url http://www.swagger.io/support
// @contact.email support@swagger.io

// @license.name Apache 2.0
// @license.url http://www.apache.org/licenses/LICENSE-2.0.html

// @host localhost:8080
// @BasePath /

// KeyGenerateRequest represents the request for key generation
type KeyGenerateRequest struct {
	ID string `json:"id" binding:"required" example:"my-key-id"`
}

// KeyGenerateResponse represents the response for key generation
type KeyGenerateResponse struct {
	ID string `json:"id" example:"my-key-id"`
}

// KeyGetResponse represents the response for getting a key
type KeyGetResponse struct {
	ID        string `json:"id" example:"my-key-id"`
	PublicKey string `json:"publicKey" example:"-----BEGIN RSA PUBLIC KEY-----\n..."`
}

// CertificateIssueRequest represents the request for issuing a certificate
type CertificateIssueRequest struct {
	CSR  string `json:"csr" binding:"required" example:"-----BEGIN CERTIFICATE REQUEST-----\nMIICgjCCAWoCAQAwPTELMAkGA1UEBhMCVk4xFDASBgNVBAoMC0V4YW1wbGUgT3JnMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC7ol+rgjOKsTGMvsQRssTJxEWbgK4TarhCt6OCg/WTYiY8+XOOOSvLzBaBCrKWudZSkiivlmoj+iwnhcX/ufJdErWGR1ANcF2x5o5kZ58I9IVdduJaHsN+dkJdNukpFzgvI4Hk6Tha88Hs5DyIcPVfU19zDX2oDpg3hvWb1F0EQOCE0+iV4eu4yUpNuEfemoRHFrE6Lo/4AAqTlhutyM0dvSOVaqcsgWY/9ioqdP1OWsxHHADKek5j70xd+uujAMgiozrapucPNK5YqC09BoQdAb84gGrvwM6jg9ytyYHK02/I0cpN08Q1+oSJVIKzOTSbJPvgSXdnElQ9aqsIX5GlAgMBAAGgADANBgkqhkiG9w0BAQsFAAOCAQEAIxXs09E/K2nhJMXoYoRmU4Fi67FWUYEAgI+KVQAJ/rrziUj4kqZ8T1Krq2FulapCPwBwMtpUCm4xAslGemvSfNOsbnDUmCp2RRZkeDbkYAgi2J3WLpPegWw4gnus/SWLrdaNudjoRJJIo1hcRot2Ia7VmACrMz9S9G/OjOUvF/6hKUsIiNIuM9muxUBkb2UX8YGxJQK8iEp1v0MRE/38TS5FFmgIOyWw4If/fqQak/fmiGM3rolvqU8btb0hfkM0bGPmNSUO5C1rphqIeA/5rUrdI6tryo+aqPg4lDORI2xV9C/egptl4hRPdMSGHVJrTSlfy4jkJ1LYkQyC+zYz8g==\n-----END CERTIFICATE REQUEST-----"`
	CAID int    `json:"ca_id" binding:"required" example:"1"`
}

// CertificateRevokeRequest represents the request for revoking a certificate
type CertificateRevokeRequest struct {
	SerialNumber string `json:"serial_number" binding:"required" example:"123456789"`
	Reason       string `json:"reason" binding:"required" example:"compromised"`
}

// CertificateRevokeResponse represents the response for certificate revocation
type CertificateRevokeResponse struct {
	Message string `json:"message" example:"Certificate revoked"`
}

// CreateCARequest represents the request for creating a new CA
type CreateCARequest struct {
	Name       string `json:"name" binding:"required" example:"MyRootCA"`
	Type       string `json:"type" binding:"required" example:"root"`
	ParentCAID *int   `json:"parent_ca_id,omitempty" example:"1"`
}

// CreateCAResponse represents the response for CA creation
type CreateCAResponse struct {
	ID      int    `json:"id" example:"1"`
	Name    string `json:"name" example:"MyRootCA"`
	Type    string `json:"type" example:"root"`
	CertPEM string `json:"cert_pem" example:"-----BEGIN CERTIFICATE-----\n..."`
	Message string `json:"message" example:"CA created successfully"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error string `json:"error" example:"Invalid request"`
}

// CAListResponse represents the response for listing CAs
type CAListResponse struct {
	CAs   []model.CA `json:"cas"`
	Total int        `json:"total" example:"5"`
}

// CAUpdateStatusRequest represents the request for updating CA status
type CAUpdateStatusRequest struct {
	Status string `json:"status" binding:"required" example:"revoked"`
}

// CARevokeRequest represents the request for revoking a CA
type CARevokeRequest struct {
	Reason string `json:"reason" binding:"required" example:"keyCompromise"`
}

// CAChainResponse represents the response for CA chain
type CAChainResponse struct {
	Chain []model.CA `json:"chain"`
}

// CertificateListResponse represents the response for listing certificates
type CertificateListResponse struct {
	Certificates []model.Certificate `json:"certificates"`
	Total        int                 `json:"total" example:"10"`
}

type App struct {
	keyService service.KeyManagementService
	caService  ca_service.CaService
	db         *sql.DB
}

// @Summary Generate a new key pair
// @Description Generate a new RSA key pair with the specified ID
// @Tags Key Management
// @Accept json
// @Produce json
// @Param request body KeyGenerateRequest true "Key generation request"
// @Success 200 {object} KeyGenerateResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /keymanagement/generate [post]
func (app *App) GenerateKeyPair(c *gin.Context) {
	var req KeyGenerateRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}

	keyPair, err := app.keyService.GenerateKeyPair(req.ID)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(200, KeyGenerateResponse{ID: keyPair.ID})
}

// @Summary Get a key pair by ID
// @Description Retrieve a key pair by its ID and return the public key
// @Tags Key Management
// @Accept json
// @Produce json
// @Param id path string true "Key ID"
// @Success 200 {object} KeyGetResponse
// @Failure 500 {object} ErrorResponse
// @Router /keymanagement/{id} [get]
func (app *App) GetKeyPair(c *gin.Context) {
	id := c.Param("id")
	keyPair, err := app.keyService.GetKeyPair(id)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(200, KeyGetResponse{
		ID:        keyPair.ID,
		PublicKey: string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(keyPair.PublicKey)})),
	})
}

// @Summary Issue a new certificate
// @Description Issue a new certificate from a Certificate Signing Request (CSR)
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param request body CertificateIssueRequest true "Certificate issuance request"
// @Success 200 {object} model.Certificate "Certificate details with PEM data"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/issue [post]
func (app *App) IssueCertificate(c *gin.Context) {
	ctx := context.Background()
	var req CertificateIssueRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(400, ErrorResponse{Error: err.Error()})
		return
	}

	// Process CSR to handle escaped newlines from JSON
	processedCSR := strings.ReplaceAll(req.CSR, "\\n", "\n")

	fmt.Println("Received CSR:", processedCSR)
	certificate, err := app.caService.IssueCertificate(ctx, processedCSR, req.CAID)
	if err != nil {
		c.JSON(500, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, certificate)
}

// @Summary Revoke a certificate
// @Description Revoke a certificate by its serial number with a specified reason
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param request body CertificateRevokeRequest true "Certificate revocation request"
// @Success 200 {object} CertificateRevokeResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/revoke [post]
func (app *App) RevokeCertificate(c *gin.Context) {
	ctx := context.Background()
	var req CertificateRevokeRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}
	err := app.caService.RevokeCertificate(ctx, req.SerialNumber, model.RevocationReason(req.Reason))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, CertificateRevokeResponse{Message: "Certificate revoked"})
}

// @Summary Get Certificate Revocation List (CRL) as file
// @Description Retrieve the current Certificate Revocation List in standard CRL format
// @Tags Certificate Authority
// @Accept json
// @Produce application/pkix-crl
// @Param ca_id query int true "Certificate Authority ID"
// @Success 200 {string} string "CRL in PEM format"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /crl.pem [get]
func (app *App) GetCRLFile(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Query("ca_id")
	if caIDStr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "ca_id parameter is required"})
		return
	}

	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	crlPEM, err := app.caService.GetCRL(ctx, caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Set proper headers for CRL file
	c.Header("Content-Type", "application/pkix-crl")
	c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"ca-%d-crl.pem\"", caID))
	c.Data(http.StatusOK, "application/pkix-crl", crlPEM)
}

// @Summary Get Certificate Revocation List (CRL)
// @Description Retrieve the current Certificate Revocation List
// @Tags Certificate Authority
// @Accept json
// @Produce application/x-pem-file
// @Param ca_id query int true "Certificate Authority ID"
// @Success 200 {string} string "PEM encoded CRL"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/crl [get]
func (app *App) GetCRL(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Query("ca_id")
	if caIDStr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "ca_id parameter is required"})
		return
	}

	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	crlPEM, err := app.caService.GetCRL(ctx, caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.Data(http.StatusOK, "application/x-pem-file", crlPEM)
}

// @Summary Create a new Certificate Authority
// @Description Create a new Certificate Authority (CA) - either root CA or subordinate CA
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param request body CreateCARequest true "CA creation request"
// @Success 200 {object} CreateCAResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/create [post]
func (app *App) CreateCA(c *gin.Context) {
	var req CreateCARequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	ctx := context.Background()

	// Convert string type to model.CAType
	var caType model.CAType
	switch req.Type {
	case "root":
		caType = model.RootCAType
	case "sub":
		caType = model.SubordinateCAType
	default:
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "Invalid CA type. Must be 'root' or 'sub'"})
		return
	}

	// Create a new CA
	ca, err := app.caService.CreateCA(ctx, req.Name, caType, req.ParentCAID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}
	c.JSON(http.StatusOK, CreateCAResponse{
		ID:      ca.ID,
		Name:    ca.Name,
		Type:    req.Type,
		CertPEM: ca.CertPEM,
		Message: "CA created successfully",
	})
}

// @Summary Get all Certificate Authorities
// @Description Retrieve all Certificate Authorities
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Success 200 {object} CAListResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca [get]
func (app *App) GetAllCAs(c *gin.Context) {
	ctx := context.Background()

	cas, err := app.caService.GetAllCAs(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, CAListResponse{
		CAs:   cas,
		Total: len(cas),
	})
}

// @Summary Get a Certificate Authority by ID
// @Description Retrieve a specific Certificate Authority by its ID
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param id path int true "CA ID"
// @Success 200 {object} model.CA
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/{id} [get]
func (app *App) GetCA(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Param("id")
	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	ca, err := app.caService.GetCA(ctx, caID)
	if err != nil {
		c.JSON(http.StatusNotFound, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, ca)
}

// @Summary Get Certificate Authority chain
// @Description Retrieve the certificate chain for a specific CA (from CA to root)
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param id path int true "CA ID"
// @Success 200 {object} CAChainResponse
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/{id}/chain [get]
func (app *App) GetCAChain(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Param("id")
	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	chain, err := app.caService.GetCAChain(ctx, caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, CAChainResponse{Chain: chain})
}

// @Summary Update Certificate Authority status
// @Description Update the status of a Certificate Authority
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param id path int true "CA ID"
// @Param request body CAUpdateStatusRequest true "Status update request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/{id}/status [put]
func (app *App) UpdateCAStatus(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Param("id")
	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	var req CAUpdateStatusRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	err := app.caService.UpdateCAStatus(ctx, caID, req.Status)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{"message": "CA status updated successfully"})
}

// @Summary Revoke a Certificate Authority
// @Description Revoke a Certificate Authority with a specified reason
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param id path int true "CA ID"
// @Param request body CARevokeRequest true "CA revocation request"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/{id}/revoke [post]
func (app *App) RevokeCA(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Param("id")
	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	var req CARevokeRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: err.Error()})
		return
	}

	err := app.caService.RevokeCA(ctx, caID, model.RevocationReason(req.Reason))
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{"message": "CA revoked successfully"})
}

// @Summary Delete a Certificate Authority
// @Description Soft delete a Certificate Authority (mark as deleted)
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Param id path int true "CA ID"
// @Success 200 {object} map[string]string
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ca/{id} [delete]
func (app *App) DeleteCA(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Param("id")
	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	err := app.caService.DeleteCA(ctx, caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, map[string]string{"message": "CA deleted successfully"})
}

// @Summary Get all certificates
// @Description Retrieve all certificates from the database
// @Tags Certificate Authority
// @Accept json
// @Produce json
// @Success 200 {object} CertificateListResponse
// @Failure 500 {object} ErrorResponse
// @Router /certificates [get]
func (app *App) GetAllCertificates(c *gin.Context) {
	ctx := context.Background()

	certificates, err := app.caService.GetAllCertificates(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	c.JSON(http.StatusOK, CertificateListResponse{
		Certificates: certificates,
		Total:        len(certificates),
	})
}

// @Summary Handle OCSP request
// @Description Handle Online Certificate Status Protocol requests to check certificate status
// @Tags Certificate Authority
// @Accept application/ocsp-request
// @Produce application/ocsp-response
// @Param ca_id query int true "Certificate Authority ID"
// @Param request body string true "OCSP request in DER format"
// @Success 200 {string} string "OCSP response in DER format"
// @Failure 400 {object} ErrorResponse
// @Failure 500 {object} ErrorResponse
// @Router /ocsp [post]
func (app *App) HandleOCSP(c *gin.Context) {
	ctx := context.Background()

	caIDStr := c.Query("ca_id")
	if caIDStr == "" {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "ca_id parameter is required"})
		return
	}

	caID := 0
	if _, err := fmt.Sscanf(caIDStr, "%d", &caID); err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "invalid ca_id parameter"})
		return
	}

	// Read OCSP request from body
	requestData, err := c.GetRawData()
	if err != nil {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "failed to read request body"})
		return
	}

	if len(requestData) == 0 {
		c.JSON(http.StatusBadRequest, ErrorResponse{Error: "empty OCSP request"})
		return
	}

	// Handle OCSP request
	responseData, err := app.caService.HandleOCSPRequest(ctx, requestData, caID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, ErrorResponse{Error: err.Error()})
		return
	}

	// Set proper headers for OCSP response
	c.Header("Content-Type", "application/ocsp-response")
	c.Header("Cache-Control", "max-age=86400") // Cache for 24 hours
	c.Data(http.StatusOK, "application/ocsp-response", responseData)
}

func main() {
	// Load unified config
	appCfg, err := config.LoadConfig()
	if err != nil {
		panic(err)
	}

	// Initialize PostgreSQL connection.
	db, err := sql.Open("pgx", appCfg.CA.Database.DSN)
	if err != nil {
		panic("failed to connect to database: " + err.Error())
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		panic("failed to ping database: " + err.Error())
	}

	repo, err := repository.NewSoftHsmKeyPairRepository(
		appCfg.KeyManagement.SoftHSM.Module,
		appCfg.KeyManagement.SoftHSM.Slot,
		appCfg.KeyManagement.SoftHSM.Pin,
	)
	if err != nil {
		panic(err)
	}
	caRepo, err := ca_repository.NewRepository(db)
	if err != nil {
		panic(err)
	}

	keyService := service.NewKeyManagementService(repo)
	caService := ca_service.NewCaService(caRepo, keyService, appCfg)

	app := &App{keyService: keyService, caService: caService, db: db}

	r := gin.Default()
	gin.SetMode(gin.ReleaseMode)

	// Swagger endpoint
	r.GET("/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))

	r.POST("/keymanagement/generate", app.GenerateKeyPair)
	r.GET("/keymanagement/:id", app.GetKeyPair)

	r.POST("/ca/issue", app.IssueCertificate)
	r.POST("/ca/revoke", app.RevokeCertificate)
	r.GET("/ca/crl", app.GetCRL)
	r.GET("/crl.pem", app.GetCRLFile)
	r.POST("/ca/create", app.CreateCA)
	r.GET("/ca", app.GetAllCAs)
	r.GET("/ca/:id", app.GetCA)
	r.GET("/ca/:id/chain", app.GetCAChain)
	r.PUT("/ca/:id/status", app.UpdateCAStatus)
	r.POST("/ca/:id/revoke", app.RevokeCA)
	r.DELETE("/ca/:id", app.DeleteCA)
	r.GET("/certificates", app.GetAllCertificates)
	r.POST("/ocsp", app.HandleOCSP)

	go func() {
		if err := r.Run(":8080"); err != nil {
			panic(err)
		}
	}()

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	repo.Finalize()
}
